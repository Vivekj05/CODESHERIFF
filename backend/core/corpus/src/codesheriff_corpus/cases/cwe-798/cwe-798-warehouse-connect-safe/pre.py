def connect():
    return psycopg.connect(os.environ["WAREHOUSE_DSN"])
