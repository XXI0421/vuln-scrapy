import scrapy, base64, re, os
from fofa_spider.items import AssetItem

class FofaSpider(scrapy.Spider):
    name = "fofa"
    allowed_domains = ["fofa.info"]

    query = 'protocol="http"'   # 默认查询，可 -a query=xxx 覆盖
    size  = 50               # 可 -a size=xxx 覆盖

    # 框架指纹正则
    FRAMEWORK_PATTERN = re.compile(
        r"(thinkphp|spring|weblogic|jboss|struts|django|flask|laravel|wordpress|drupal|shiro|nginx|apache|iis)",
        re.I
    )

    def __init__(self, email=None, key=None, query=None, size=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.email = email or os.getenv("FOFA_EMAIL", "").strip()
        self.key   = key   or os.getenv("FOFA_KEY", "").strip()
        if query: self.query = query
        if size:  self.size  = int(size)
        if not self.email or not self.key:
            raise ValueError("FOFA_EMAIL / FOFA_KEY 缺失")

    def start_requests(self):
        qbase64 = base64.b64encode(self.query.encode()).decode()
        url = (
            f"https://fofa.info/api/v1/search/all"
            f"?email={self.email}&key={self.key}&qbase64={qbase64}"
            f"&size={self.size}&fields=ip,port,protocol,host,title,icp,country,city,server,banner"
        )
        yield scrapy.Request(url, callback=self.parse)

    def parse(self, response):
        data = response.json()
        if data.get("error"):
            self.logger.error("FOFA API 错误: %s", data.get("errmsg"))
            return
        for row in data.get("results", []):
            yield AssetItem(
                ip       = row[0],
                port     = int(row[1]),
                protocol = row[2],
                host     = row[3],
                title    = row[4],
                icp      = row[5],
                country  = row[6],
                city     = row[7],
                server   = row[8],
                banner   = row[9],
            )

    def extract_framework(self, text):
        m = self.FRAMEWORK_PATTERN.search(text)
        return m.group(1).lower() if m else None