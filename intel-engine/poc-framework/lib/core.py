from abc import ABC, abstractmethod

class POCBase(ABC):
    """所有 PoC 必须实现 verify 方法"""
    @abstractmethod
    def verify(self, url: str) -> bool:
        """返回 True 表示漏洞存在"""
        ...