"""Where an AS's IPv4 addresses geolocate, for the /AS<n> map.

An AS announces thousands of prefixes, so the map reads a bounded sample of
addresses (`sample_addresses`), asks a `place` function where each one is, and
folds the answers into city dots (`footprint`). Pure: `place` comes in as an
argument (lookup.as_footprint passes GeoIpManager.place), so nothing here
reads a database. A sample stands for the address space of its prefix, so
shares are fractions of address space, not of samples. Each drawn city also
lists the announced prefixes that have addresses there (`_attach`), with the
share of each prefix placed in that city."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Sequence

from config import AS_MAP_MAX_DOTS
from geo import coordinate_precision


def _collapsed(prefixes: Sequence[str]) -> list[ipaddress.IPv4Network]:
    """The IPv4 blocks of `prefixes` with nested and adjacent ones merged,
    largest first, so no address is sampled or weighed twice."""
    networks = []
    for text in prefixes:
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            continue
        if network.version == 4:
            networks.append(network)
    blocks = list(ipaddress.collapse_addresses(networks))
    blocks.sort(key=lambda n: (-n.num_addresses, int(n.network_address)))
    return blocks


def sample_addresses(prefixes: Sequence[str], budget: int) -> list[tuple[str, float]]:
    """(address, weight) pairs, at most `budget` of them, weights being the
    address counts each sample stands for.

    Largest prefixes first, each getting a share of the budget in proportion
    to its size and never more than one sample per /24 (GeoLite2 does not
    split finer in practice). When the budget runs out the remaining, smaller
    prefixes go unsampled. IPv6 and unparsable entries are ignored."""
    networks = _collapsed(prefixes)
    total = sum(n.num_addresses for n in networks)
    samples: list[tuple[str, float]] = []
    remaining = budget
    for network in networks:
        if remaining <= 0:
            break
        size = network.num_addresses
        k = min(max(1, round(budget * size / total)), max(1, size // 256), remaining)
        step = size // k
        base = int(network.network_address)
        for i in range(k):
            samples.append((str(ipaddress.IPv4Address(base + i * step)), size / k))
        remaining -= k
    return samples


def _listed(prefixes: Sequence[str]) -> list[ipaddress.IPv4Network]:
    """The IPv4 prefixes as announced: de-duplicated, in input order."""
    seen: dict[ipaddress.IPv4Network, None] = {}
    for text in prefixes:
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            continue
        if network.version == 4:
            seen.setdefault(network)
    return list(seen)


def _first_address(network: ipaddress.IPv4Network) -> str:
    """An address inside `network` that is not its network address, unless it
    has no other (a /31 or /32)."""
    base = int(network.network_address)
    return str(ipaddress.IPv4Address(base + 1 if network.prefixlen < 31 else base))


def _attach(
    listed: list[ipaddress.IPv4Network],
    samples: list[tuple[str, float]],
    keys: list[tuple | None],
    drawn: set[tuple],
    place: Callable[[str], dict | None],
) -> dict[tuple, list[dict]]:
    """For each drawn city key, the listed prefixes with addresses there.

    `keys` holds each sample's city key, None when it is not city level. A
    sample counts for every listed prefix that contains it (one dict per
    prefix length, keyed by the masked network, not a scan of all prefixes).
    A listed prefix no sample fell in gets one extra `place` read, after all
    the sample reads, and joins the city it lands in when that is drawn."""
    by_length: dict[int, dict[int, ipaddress.IPv4Network]] = {}
    for network in listed:
        by_length.setdefault(network.prefixlen, {})[int(network.network_address)] = (
            network
        )
    total: dict[ipaddress.IPv4Network, float] = {}
    here: dict[ipaddress.IPv4Network, dict[tuple, list]] = {}
    for (address, weight), key in zip(samples, keys):
        value = int(ipaddress.IPv4Address(address))
        for length, networks in by_length.items():
            mask = (0xFFFFFFFF << (32 - length)) & 0xFFFFFFFF
            network = networks.get(value & mask)
            if network is None:
                continue
            total[network] = total.get(network, 0.0) + weight
            if key in drawn:
                # [weight in this city, first address placed there]
                entry = here.setdefault(network, {}).setdefault(key, [0.0, address])
                entry[0] += weight
    pairs: dict[tuple, list[tuple]] = {key: [] for key in drawn}
    for network, cities in here.items():
        for key, (weight, address) in cities.items():
            if address == str(network.network_address) and network.prefixlen < 31:
                address = _first_address(network)
            pairs[key].append((network, round(weight / total[network], 4), address))
    for network in listed:
        if network in total:
            continue
        address = _first_address(network)
        found = place(address)
        if (
            found is None
            or not found.get("city")
            or coordinate_precision(found) != "city"
        ):
            continue
        key = _city_key(found)
        if key in drawn:
            pairs[key].append((network, 1.0, address))
    return {
        key: [
            {"prefix": str(n), "here": share, "address": address}
            for n, share, address in sorted(
                found, key=lambda t: (-t[1], t[0].prefixlen, int(t[0].network_address))
            )
        ]
        for key, found in pairs.items()
    }


def _city_key(found: dict) -> tuple:
    return (
        found.get("country"),
        found.get("city"),
        round(found["lat"], 1),
        round(found["lon"], 1),
    )


def footprint(
    prefixes: Sequence[str],
    place: Callable[[str], dict | None],
    budget: int,
    max_dots: int = AS_MAP_MAX_DOTS,
) -> dict:
    """The sampled space split into city dots, country-level space and space
    no database places.

    A sample is city-level by `geo.coordinate_precision`, the site's one
    precision rule, and only when it names a city: GeoLite2's country-default
    record (a centroid with a 200 km radius and no city) is country level.
    Samples in the same named city (within a tenth of a degree) merge into one
    dot at their weighted mean. `sampled_share` is the sampled space over all
    the IPv4 space of `prefixes`, so a page can say how much of the AS the map
    looked at."""
    samples = sample_addresses(prefixes, budget)
    total_space = sum(n.num_addresses for n in _collapsed(prefixes))
    sampled = sum(weight for _, weight in samples)
    cities: dict[tuple, list] = {}
    country_level = unplaced = 0.0
    keys: list[tuple | None] = []
    for address, weight in samples:
        found = place(address)
        key = None
        if found is None:
            unplaced += weight
        elif not found.get("city") or coordinate_precision(found) != "city":
            country_level += weight
        else:
            key = _city_key(found)
            entry = cities.setdefault(key, [0.0, 0.0, 0.0])
            entry[0] += weight
            entry[1] += found["lat"] * weight
            entry[2] += found["lon"] * weight
        keys.append(key)

    def share(weight: float) -> float:
        return round(weight / sampled, 4) if sampled else 0.0

    ranked = [
        (
            key,
            {
                "name": key[1],
                "country": key[0],
                "lat": round(lat / weight, 4),
                "lon": round(lon / weight, 4),
                "share": share(weight),
            },
        )
        for key, (weight, lat, lon) in cities.items()
    ]
    ranked.sort(
        key=lambda r: (-r[1]["share"], r[1]["name"] or "", r[1]["country"] or "")
    )
    ranked = ranked[:max_dots]
    attached = _attach(
        _listed(prefixes), samples, keys, {key for key, _ in ranked}, place
    )
    return {
        "cities": [{**dot, "prefixes": attached[key]} for key, dot in ranked],
        "country_level_share": share(country_level),
        "unplaced_share": share(unplaced),
        "sampled_share": round(sampled / total_space, 4) if total_space else 0.0,
        "samples": len(samples),
    }
