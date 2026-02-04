import requests

baseurl = "http://127.0.0.1:8000"


class Client():
    def __init__(self, baseurl):
        self.baseurl = baseurl

    def get(self, url):
        return requests.get(self.baseurl + url)


class TestBasic:
    client = Client(baseurl)

    def test_get_self_info(self):
        response = self.client.get("/")
        assert response.status_code == 200
        json_data = response.json()
        assert "address" in json_data
        assert "location" in json_data
        assert "whois" in json_data

    def test_get_domain_info(self):
        response = self.client.get("/google.com")
        assert response.status_code == 200
        json_data = response.json()
        assert "domain_name" in json_data['whois']
        assert "google.com" in json_data["whois"]["domain_name"].lower()

    def test_get_ip_info(self):
        response = self.client.get("/8.8.8.8")
        assert response.status_code == 200
        json_data = response.json()
        assert json_data["location"]["ip"] == "8.8.8.8"

    def test_not_found(self):
        response = self.client.get("/admin/nonexistent")
        assert response.status_code == 404
