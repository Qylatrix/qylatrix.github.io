from flask import Flask, make_response
from datetime import datetime

def generate_sitemap():
    """Generate XML sitemap for the website"""
    pages = [
        {'url': '/', 'priority': '1.0', 'changefreq': 'weekly'},
        {'url': '/academy', 'priority': '0.9', 'changefreq': 'weekly'},
        {'url': '/tools', 'priority': '0.8', 'changefreq': 'weekly'},
        {'url': '/team', 'priority': '0.7', 'changefreq': 'monthly'},
        {'url': '/contact', 'priority': '0.8', 'changefreq': 'monthly'},
        {'url': '/login', 'priority': '0.6', 'changefreq': 'monthly'},
        {'url': '/register', 'priority': '0.6', 'changefreq': 'monthly'},
    ]
    
    sitemap_xml = ['<?xml version="1.0" encoding="UTF-8"?>']
    sitemap_xml.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')
    
    base_url = 'https://qylatrix.pythonanywhere.com'
    lastmod = datetime.now().strftime('%Y-%m-%d')
    
    for page in pages:
        sitemap_xml.append('  <url>')
        sitemap_xml.append(f'    <loc>{base_url}{page["url"]}</loc>')
        sitemap_xml.append(f'    <lastmod>{lastmod}</lastmod>')
        sitemap_xml.append(f'    <changefreq>{page["changefreq"]}</changefreq>')
        sitemap_xml.append(f'    <priority>{page["priority"]}</priority>')
        sitemap_xml.append('  </url>')
    
    sitemap_xml.append('</urlset>')
    
    return '\n'.join(sitemap_xml)
