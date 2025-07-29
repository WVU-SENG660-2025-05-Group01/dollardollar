import statistics
from datetime import datetime, timedelta

# Suspicious activity detection for bank transactions
# This function can be called after importing or syncing transactions for a user/account

def detect_suspicious_activity(transactions, user_profile=None, threshold_large=10000, rapid_count=3, rapid_minutes=10, unusual_merchant_window_days=30):
    """
    Detect suspicious activity in a list of transactions.
    Args:
        transactions: List of dicts with keys: amount, date, description, account_id, etc.
        user_profile: Optional dict with user/account historical data for more advanced checks.
        threshold_large: Amount above which a transaction is considered unusually large.
        rapid_count: Number of transactions in rapid succession to flag.
        rapid_minutes: Time window (minutes) for rapid transaction detection.
        unusual_merchant_window_days: Days to look back for new merchants/locations.
    Returns:
        List of suspicious activity alerts (dicts).
    """
    alerts = []
    if not transactions:
        return alerts

    # Sort transactions by date (assume date is datetime or ISO string)
    txs = sorted(transactions, key=lambda t: t['date'] if isinstance(t['date'], datetime) else datetime.fromisoformat(t['date']))

    # 1. Large transaction detection
    for tx in txs:
        if abs(tx['amount']) >= threshold_large:
            alerts.append({
                'type': 'large_transaction',
                'transaction': tx,
                'message': f"Unusually large transaction: ${tx['amount']:.2f} on {tx['date']}"
            })

    # 2. Rapid multiple transactions detection
    for i in range(len(txs) - rapid_count + 1):
        window = txs[i:i+rapid_count]
        times = [t['date'] if isinstance(t['date'], datetime) else datetime.fromisoformat(t['date']) for t in window]
        if (times[-1] - times[0]).total_seconds() <= rapid_minutes * 60:
            alerts.append({
                'type': 'rapid_transactions',
                'transactions': window,
                'message': f"{rapid_count} transactions within {rapid_minutes} minutes: {[t['amount'] for t in window]}"
            })

    # 3. Unusual merchant/location detection (simple: new description)
    if user_profile and 'recent_descriptions' in user_profile:
        known_desc = set(user_profile['recent_descriptions'])
        for tx in txs:
            desc = tx.get('description', '').strip().lower()
            if desc and desc not in known_desc:
                alerts.append({
                    'type': 'unusual_merchant',
                    'transaction': tx,
                    'message': f"Transaction at new merchant/location: '{desc}' on {tx['date']}"
                })

    # 4. Sudden change in spending pattern (simple: >2x std deviation from mean)
    if len(txs) >= 10:
        amounts = [abs(t['amount']) for t in txs]
        mean = statistics.mean(amounts)
        stdev = statistics.stdev(amounts)
        for tx in txs:
            if abs(tx['amount']) > mean + 2 * stdev:
                alerts.append({
                    'type': 'spending_pattern_change',
                    'transaction': tx,
                    'message': f"Transaction ${tx['amount']:.2f} is much higher than your usual spending (${mean:.2f})"
                })

    return alerts
