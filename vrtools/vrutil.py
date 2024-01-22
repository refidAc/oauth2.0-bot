from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

def url_change_width(url, new_width):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params['w'] = [str(new_width)]
    new_query = urlencode(params, doseq=True)
    new_parsed = parsed._replace(query=new_query)
    new_url = urlunparse(new_parsed)
    return new_url