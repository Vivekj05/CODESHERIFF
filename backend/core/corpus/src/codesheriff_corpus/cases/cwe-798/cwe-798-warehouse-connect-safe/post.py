def connect():
    return psycopg.connect(
        os.environ["WAREHOUSE_DSN"], application_name="analytics-reporting"
    )
