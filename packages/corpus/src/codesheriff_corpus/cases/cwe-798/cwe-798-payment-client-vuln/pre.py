def build_payment_client():
    return StripeClient(api_key=os.environ["STRIPE_API_KEY"])
