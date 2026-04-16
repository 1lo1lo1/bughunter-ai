import yaml
import re

class TemplateEngine:
    def __init__(self, template_path: str):
        with open(template_path, 'r') as f:
            self.data = yaml.safe_load(f)

    def check(self, content: str):
        results = []
        for matcher in self.data.get('matchers', []):
            pattern = matcher.get('regex', [])[0]
            if re.search(pattern, content):
                results.append({
                    "id": self.data.get('id'),
                    "severity": self.data.get('info', {}).get('severity'),
                    "description": self.data.get('info', {}).get('description')
                })
        return results
