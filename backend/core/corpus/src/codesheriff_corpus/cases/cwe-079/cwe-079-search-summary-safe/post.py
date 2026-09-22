def search_summary(query, hits):
    return format_html("<p>{} results for <b>{}</b></p>", hits, query)
