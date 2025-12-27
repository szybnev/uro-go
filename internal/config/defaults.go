package config

// DefaultBlacklist содержит расширения файлов, которые исключаются по умолчанию
var DefaultBlacklist = []string{
	"css", "png", "jpg", "jpeg", "svg", "ico", "webp", "scss",
	"tif", "tiff", "ttf", "otf", "woff", "woff2", "gif",
	"pdf", "bmp", "eot", "mp3", "mp4", "avi",
}

// VulnParams содержит имена параметров, которые часто связаны с уязвимостями
var VulnParams = map[string]struct{}{
	// File/Path Traversal
	"file": {}, "document": {}, "folder": {}, "root": {}, "path": {},
	"pg": {}, "style": {}, "pdf": {}, "template": {}, "php_path": {},
	"doc": {}, "page": {}, "name": {}, "cat": {}, "dir": {}, "action": {},
	"board": {}, "date": {}, "detail": {}, "download": {}, "prefix": {},
	"include": {}, "inc": {}, "locate": {}, "show": {}, "site": {},
	"type": {}, "view": {}, "content": {}, "layout": {}, "mod": {},
	"conf": {}, "daemon": {}, "upload": {}, "log": {}, "ip": {}, "cli": {},

	// Command Execution
	"cmd": {}, "exec": {}, "command": {}, "execute": {}, "ping": {},
	"query": {}, "jump": {}, "code": {}, "reg": {}, "do": {}, "func": {},
	"arg": {}, "option": {}, "load": {}, "process": {}, "step": {},
	"read": {}, "function": {}, "req": {}, "feature": {}, "exe": {},
	"module": {}, "payload": {}, "run": {}, "print": {},

	// Redirect
	"callback": {}, "checkout": {}, "checkout_url": {}, "continue": {},
	"data": {}, "dest": {}, "destination": {}, "domain": {}, "feed": {},
	"file_name": {}, "file_url": {}, "folder_url": {}, "forward": {},
	"from_url": {}, "go": {}, "goto": {}, "host": {}, "html": {},
	"image_url": {}, "img_url": {}, "load_file": {}, "load_url": {},
	"login_url": {}, "logout": {}, "navigation": {}, "next": {},
	"next_page": {}, "Open": {}, "out": {}, "page_url": {}, "port": {},
	"redir": {}, "redirect": {}, "redirect_to": {}, "redirect_uri": {},
	"redirect_url": {}, "reference": {}, "return": {}, "return_path": {},
	"return_to": {}, "returnTo": {}, "return_url": {}, "rt": {}, "rurl": {},
	"target": {}, "to": {}, "uri": {}, "url": {}, "val": {}, "validate": {},
	"window": {},

	// Injection
	"q": {}, "s": {}, "search": {}, "lang": {}, "keyword": {}, "keywords": {},
	"year": {}, "email": {}, "p": {}, "jsonp": {}, "api_key": {}, "api": {},
	"password": {}, "emailto": {}, "token": {}, "username": {}, "csrf_token": {},
	"unsubscribe_token": {}, "id": {}, "item": {}, "page_id": {}, "month": {},
	"immagine": {}, "list_type": {}, "terms": {}, "categoryid": {}, "key": {},
	"l": {}, "begindate": {}, "enddate": {},

	// SQL
	"select": {}, "report": {}, "role": {}, "update": {}, "user": {},
	"sort": {}, "where": {}, "params": {}, "row": {}, "table": {},
	"from": {}, "sel": {}, "results": {}, "sleep": {}, "fetch": {},
	"order": {}, "column": {}, "field": {}, "delete": {}, "string": {},
	"number": {}, "filter": {},

	// Debug/Admin
	"access": {}, "admin": {}, "dbg": {}, "debug": {}, "edit": {},
	"grant": {}, "test": {}, "alter": {}, "clone": {}, "create": {},
	"disable": {}, "enable": {}, "make": {}, "modify": {}, "rename": {},
	"reset": {}, "shell": {}, "toggle": {}, "adm": {}, "cfg": {},
	"open": {}, "img": {}, "filename": {}, "preview": {}, "activity": {},
}
