import re
# ---------------- 内联 SVG 图标系统(零依赖, 与前端 JS 共享同一份 path 表) ----------------
# 风格: 16x16 viewBox, stroke=currentColor, stroke-width=1.5, round linecap/join。
# JS 侧经 {{ICONS_JSON}} 注入同一份表, 保证两端图标完全一致。
ICONS = {
    "wait":   '<path d="M8 1.5A6.5 6.5 0 1 1 1.5 8"/>',
    "ok":     '<circle cx="8" cy="8" r="6.5"/><path d="m5.3 8.3 1.9 1.9 3.5-4.2"/>',
    "warn":   '<path d="M8 1.8 15 13.8H1Z"/><path d="M8 6v3.4"/><path d="M8 11.9h.01"/>',
    "err":    '<circle cx="8" cy="8" r="6.5"/><path d="m5.7 5.7 4.6 4.6M10.3 5.7l-4.6 4.6"/>',
    "dot":    '<circle cx="8" cy="8" r="4.5" fill="currentColor" stroke="none"/>',
    "pause":  '<path d="M5.5 3.5v9M10.5 3.5v9"/>',
    "retry":  '<path d="M2.6 8a5.4 5.4 0 0 1 9.3-3.7M13.4 8a5.4 5.4 0 0 1-9.3 3.7"/>'
              '<path d="M12.1 1.7v2.8H9.3M3.9 14.3v-2.8h2.8"/>',
    "up":     '<circle cx="8" cy="8" r="6.5"/><path d="M8 11V5.6M5.7 7.9 8 5.6l2.3 2.3"/>',
    "bell":   '<path d="M8 2.2a3.8 3.8 0 0 0-3.8 3.8c0 3-1.1 4.1-1.7 4.8h11c-.6-.7-1.7-1.8-1.7-4.8A3.8 3.8 0 0 0 8 2.2Z"/>'
              '<path d="M6.6 12.8a1.5 1.5 0 0 0 2.8 0"/>',
    "trash":  '<path d="M2.8 4.2h10.4M6.4 4.2V2.6h3.2v1.6M4.2 4.2l.6 9.2h6.4l.6-9.2M6.7 6.8v4M9.3 6.8v4"/>',
    "box":    '<path d="M8 1.8 13.6 4.6v6.8L8 14.2 2.4 11.4V4.6Z"/><path d="M2.4 4.6 8 7.4l5.6-2.8M8 7.4v6.8"/>',
    "branch": '<circle cx="4.5" cy="3.6" r="1.7"/><circle cx="4.5" cy="12.4" r="1.7"/><circle cx="11.5" cy="5.2" r="1.7"/><path d="M4.5 5.3v5.4M11.5 6.9c0 2.6-5.3 1.8-6.5 4"/>',
    "folder": '<path d="M1.8 4.3c0-.6.5-1.1 1.1-1.1h3l1.5 1.7h5.7c.6 0 1.1.5 1.1 1.1v6c0 .6-.5 1.1-1.1 1.1H2.9c-.6 0-1.1-.5-1.1-1.1Z"/>',
    "file":   '<path d="M4 1.8h5.2L12.4 5v9.2H4Z"/><path d="M9 1.8V5h3.4"/>',
    "heart":  '<path d="M8 13.6S1.8 10.2 1.8 6C1.8 4 3.3 2.6 5.1 2.6c1.2 0 2.3.7 2.9 1.7.6-1 1.7-1.7 2.9-1.7 1.8 0 3.3 1.4 3.3 3.4 0 4.2-6.2 7.6-6.2 7.6Z"/>',
    "gauge":  '<path d="M2.4 11.2a5.9 5.9 0 1 1 11.2 0"/><path d="M8 11 10.6 6.8"/><path d="M8 11h.01"/>',
    "clock":  '<circle cx="8" cy="8" r="6.4"/><path d="M8 4.6V8l2.3 1.7"/>',
    "ext":    '<path d="M6.8 3.4H4.2c-1 0-1.8.8-1.8 1.8v6.6c0 1 .8 1.8 1.8 1.8h6.6c1 0 1.8-.8 1.8-1.8V9.2"/>'
              '<path d="M9.4 2.6h4v4M13 3 7.8 8.2"/>',
    "copy":   '<rect x="5.6" y="5.6" width="7.9" height="7.9" rx="1.3"/>'
              '<path d="M10.4 5.6V3.9c0-.7-.6-1.3-1.3-1.3H3.9c-.7 0-1.3.6-1.3 1.3v5.2c0 .7.6 1.3 1.3 1.3h1.7"/>',
    "refresh":'<path d="M13.6 8a5.6 5.6 0 1 1-1.7-4"/><path d="M12.3 1.4v2.8H9.5"/>',
    "lock":   '<rect x="3.4" y="7" width="9.2" height="6.6" rx="1.3"/><path d="M5.6 7V5.2a2.4 2.4 0 0 1 4.8 0V7"/>',
    "close":  '<path d="m4.2 4.2 7.6 7.6M11.8 4.2l-7.6 7.6"/>',
    "chev":   '<path d="m6 4 4.6 4L6 12"/>',
    "down":   '<path d="M8 2.6v9.2M4.6 8.4 8 11.8l3.4-3.4"/>',
    "cpu":    '<rect x="4" y="4" width="8" height="8" rx="1.3"/>'
              '<path d="M6.2 1.6v2M9.8 1.6v2M6.2 12.4v2M9.8 12.4v2M1.6 6.2h2M1.6 9.8h2M12.4 6.2h2M12.4 9.8h2"/>',
    "mem":    '<rect x="2.4" y="4.8" width="11.2" height="7" rx="1.1"/><path d="M5.2 8.2v1.6M8 7v2.8M10.8 8.2v1.6"/>',
    "disk":   '<ellipse cx="8" cy="3.9" rx="5.2" ry="1.9"/>'
              '<path d="M2.8 3.9v8.2c0 1.05 2.33 1.9 5.2 1.9s5.2-.85 5.2-1.9V3.9"/>'
              '<path d="M2.8 8c0 1.05 2.33 1.9 5.2 1.9s5.2-.85 5.2-1.9"/>',
    "load":   '<path d="M1.4 8.6h2.6l2-5.4 3 10 2-4.6h3.6"/>',
    "swap":   '<path d="M3.2 6.2a5.2 5.2 0 0 1 9.4-1.8M12.8 9.8a5.2 5.2 0 0 1-9.4 1.8"/>'
              '<path d="M13 2.2v2.6h-2.6M3 13.8v-2.6h2.6"/>',
    "play":   '<path d="M5.2 3.4 12.4 8l-7.2 4.6Z"/>',
    "stop":   '<rect x="4" y="4" width="8" height="8" rx="1.2"/>',
    "sun":    '<circle cx="8" cy="8" r="3.2"/>'
              '<path d="M8 1.2v1.8M8 13v1.8M1.2 8H3M13 8h1.8M3.2 3.2l1.3 1.3M11.5 11.5l1.3 1.3M12.8 3.2l-1.3 1.3M4.5 11.5l-1.3 1.3"/>',
    "moon":   '<path d="M13.4 10.4A5.8 5.8 0 0 1 5.6 2.6a6 6 0 1 0 7.8 7.8Z"/>',
    "auto":   '<circle cx="8" cy="8" r="6.4"/><path d="M8 1.6a6.4 6.4 0 0 1 0 12.8Z" fill="currentColor" stroke="none"/>',
    "home":  '<path d="M2.2 7.6 8 2.2l5.8 5.4"/><path d="M4 6.6v5.6a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V6.6"/>'
             '<path d="M6.5 13.2V9.4h3v3.8"/>',
    "back":  '<path d="m10 3.2-4.8 4.8 4.8 4.8"/>',
    "search":'<circle cx="7" cy="7" r="4.4"/><path d="m10.4 10.4 3.2 3.2"/>',
    "sort":  '<path d="M3.6 4.6h8.8M3.6 8h5.6M3.6 11.4h2.4"/>',
    "doc":   '<path d="M4 1.8h5.2L12.4 5v9.2H4Z"/><path d="M9 1.8V5h3.4M6 8h4M6 10.6h4"/>',
    "code":  '<path d="m5.4 5.2-3 2.8 3 2.8M10.6 5.2l3 2.8-3 2.8M9.2 3.2 6.8 12.8"/>',
    "img":   '<rect x="2" y="3.4" width="12" height="9.2" rx="1.2"/><circle cx="5.5" cy="6.5" r="1"/>'
             '<path d="m2.6 11.4 3.8-3 2.4 2 2-1.6 2.6 2.6"/>',
    "zip":   '<rect x="2.4" y="2.4" width="11.2" height="3" rx="1"/>'
             '<path d="M3.4 5.4v7.2a1 1 0 0 0 1 1h7.2a1 1 0 0 0 1-1V5.4"/><path d="M6.6 8.6h2.8"/>',
}

_ICO_PAT = re.compile(r"\{\{ICO:([a-z0-9_]+)(?::(\d+))?\}\}")


def icon(name, size=16, cls="ic"):
    """name -> 内联 SVG 字符串; 未知名字回退为空心圆点。"""
    path = ICONS.get(name) or ICONS["dot"]
    c = f' class="{cls}"' if cls else ""
    return (f'<svg{c} width="{size}" height="{size}" viewBox="0 0 16 16" fill="none" '
            f'stroke="currentColor" stroke-width="1.5" stroke-linecap="round" '
            f'stroke-linejoin="round" aria-hidden="true">{path}</svg>')
