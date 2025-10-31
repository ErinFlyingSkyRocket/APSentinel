from django import template
from django.utils import timezone

register = template.Library()

@register.filter
def age(dt):
    """Pretty age like '2m 13s ago' or '—' for None."""
    if not dt:
        return "—"
    delta = timezone.now() - dt
    s = int(delta.total_seconds())
    if s < 60:
        return f"{s}s ago"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m}m {s}s ago"
    h, m = divmod(m, 60)
    return f"{h}h {m}m ago"
