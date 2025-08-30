# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html
import scrapy

class AssetItem(scrapy.Item):
    ip        = scrapy.Field()
    port      = scrapy.Field()
    protocol  = scrapy.Field()
    host      = scrapy.Field()
    title     = scrapy.Field()
    banner    = scrapy.Field()
    icp       = scrapy.Field()
    country   = scrapy.Field()
    city      = scrapy.Field()
    server    = scrapy.Field()
    framework = scrapy.Field()
    last_seen = scrapy.Field()