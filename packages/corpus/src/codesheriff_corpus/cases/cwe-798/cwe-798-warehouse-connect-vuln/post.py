def connect():
    return psycopg.connect(
        "postgresql://reporting:Rep0rting-2024@analytics.internal:5432/warehouse"
    )
