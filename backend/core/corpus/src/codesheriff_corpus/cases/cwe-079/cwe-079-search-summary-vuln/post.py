def search_summary(query, hits):
    return mark_safe(f"<p>{hits} results for <b>{query}</b></p>")
