import requests

class CloudHunter:
    def __init__(self):
        self.s3_pattern = r'([a-z0-9\.\-]+\.s3\.amazonaws\.com)'

    def check_s3_bucket(self, bucket_url):
        """ამოწმებს არის თუ არა S3 Bucket ღია (Public)"""
        if not bucket_url.startswith('http'):
            bucket_url = f"https://{bucket_url}"
            
        try:
            # ვცდილობთ Bucket-ის შიგთავსის ჩამონათვალის ნახვას
            response = requests.get(bucket_url, timeout=5)
            if 'ListBucketResult' in response.text:
                return True, "Publicly Accessible (Listing Enabled)"
            elif response.status_code == 403:
                return False, "Private (Access Denied)"
        except:
            pass
        return False, "Unknown"
