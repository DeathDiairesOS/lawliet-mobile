"""Presentation groups; never rewrite parser classifications or source timestamps."""
BROWSER_REPORTS = {
    'web history','web visits','cookies','chrome browser cache','network action predictor',
    'keyword search terms','search terms',
    'browser data - history (mister skinnylegs)',
    'browser data - localstorage (mister skinnylegs)',
    'browser data - sessionstorage (mister skinnylegs)',
}


def evidence_group(category, report):
    if category == 'browser' or str(report or '').lower() in BROWSER_REPORTS:
        return 'browser'
    return category or 'external'
