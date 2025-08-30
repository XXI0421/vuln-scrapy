import random
from lib.core import POCBase
class POC(POCBase):
    def verify(self, url):
        # 强制随机命中，确保框架流程正确
        return random.choice([True, False])