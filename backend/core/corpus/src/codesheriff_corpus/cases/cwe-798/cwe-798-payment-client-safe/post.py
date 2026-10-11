def build_payment_client():
    api_key = os.environ["STRIPE_API_KEY"]
    return StripeClient(api_key=api_key, timeout=REQUEST_TIMEOUT)
