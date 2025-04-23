import requests
import urllib.parse

class OneAPIManager:
    
    def __init__(self, url, access_token):
        self.base_url = url
        self.access_token = access_token
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": self.access_token
        }

    def get_channel(self, id):
        url = urllib.parse.urljoin(self.base_url, f"/api/channel/{id}")

        response = requests.get(url, headers=self.headers)
        return response

    def get_channels(self, page, pagesize):
        url = urllib.parse.urljoin(self.base_url, f"/api/channel/?p={page}&page_size={pagesize}")

        response = requests.get(url, headers=self.headers)
        return response

    # Support multiple keys separated by '\n'
    def add_channel(self, name, base_url, key, models, tags = "", rate_limit_count = 0):
        url = urllib.parse.urljoin(self.base_url, "/api/channel")

        data = {"name": name,
                "type": 1,
                "key": key,
                "openai_organization": "",
                "base_url": base_url,
                "other": "",
                "model_mapping":"",
                "status_code_mapping":"",
                "headers":"",
                "models": ','.join(models),
                "auto_ban":0,
                "is_image_url_enabled": 0,
                "model_test": models[0],
                "tested_time": 0,
                "priority": 0,
                "weight": 0,
                "groups": ["default"],
                "proxy_url": "",
                "region": "",
                "sk": "",
                "ak": "",
                "project_id": "",
                "client_id": "",
                "client_secret": "",
                "refresh_token": "",
                "gcp_account": "",
                "rate_limit_count":rate_limit_count,
                "gemini_model":"",
                "tags": tags,
                "rate_limited":rate_limit_count > 0,
                "is_tools": False,
                "claude_original_request": False,
                "group":"default"
        }

        response = requests.post(url, json=data, headers=self.headers)
        return response
    
    # 批量添加Cursor渠道的简便方法
    def batch_add_channel(self, tokens, channel_url, models=None, tags="Cursor"):
        from cursor import Cursor
        if models is None:
            models = Cursor.models
            
        batch_tokens = '\n'.join(tokens)
        response = self.add_channel(
            name="Cursor", 
            base_url=channel_url, 
            key=batch_tokens, 
            models=models, 
            tags=tags
        )
        
        print(f'[OneAPI] Add Channels Batch. Status Code: {response.status_code}, Response: {response.json()}')
        return response
    
    def delete_channel(self, id):
        url = urllib.parse.urljoin(self.base_url, f"/api/channel/{id}")

        response = requests.delete(url, headers=self.headers)
        return response
    
    def enable_channel(self, id):
        url = urllib.parse.urljoin(self.base_url, f"/api/channel")
        data = {
            "id": id,
            "status": 1
        }

        response = requests.put(url, json=data, headers=self.headers)
        return response

    def disable_channel(self, id):
        url = urllib.parse.urljoin(self.base_url, f"/api/channel")
        data = {
            "id": id,
            "status": 2
        }

        response = requests.put(url, json=data, headers=self.headers)
        return response

    def test_channel(self, id, model = ""):
        url = urllib.parse.urljoin(self.base_url, f"/api/channel/test/{id}?model={model}")

        response = requests.get(url, headers=self.headers)
        return response
