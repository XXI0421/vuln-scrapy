import scrapy, json, sqlite3, datetime, zipfile, io, requests
from pathlib import Path

class CveNvdSpider(scrapy.Spider):
    name = "cve_nvd"
    start_urls = ["https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip"]

    def parse(self, response):
        # 下载 zip
        z = zipfile.ZipFile(io.BytesIO(response.body))
        json_file = z.namelist()[0]          # nvdcve-1.1-recent.json
        data = json.loads(z.read(json_file).decode())

        for item in data.get("CVE_Items", []):
            cve_id = item["cve"]["CVE_data_meta"]["ID"]
            desc   = next(
                (d["value"] for d in item["cve"]["description"]["description_data"] if d["lang"] == "en"),
                ""
            )
            cvss   = 0.0
            if "baseMetricV3" in item.get("impact", {}):
                cvss = item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            elif "baseMetricV2" in item.get("impact", {}):
                cvss = item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]

            yield {
                "cve": cve_id,
                "cvss": cvss,
                "description": desc,
                "patch_commit": "",   # 后续任务再补
                "exp_url": ""
            }