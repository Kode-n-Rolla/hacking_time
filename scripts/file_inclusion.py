from urllib.request import urlopen

content = urlopen(
  "file://yoogle.com/etc/passwd", timeout=2,
  ).read().decode('utf-8')

print(content)
