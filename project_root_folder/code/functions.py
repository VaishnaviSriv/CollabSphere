from datetime import datetime
def process_date(input_str_date):
    # Parse the input date string into a date object
    input_date = datetime.strptime(input_str_date, '%Y-%m-%d').date()
    return input_date

def processing_date(date_string):
    try:
        # Parse the full datetime string
        dt = datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S.%f")
        # Format it to show only the date
        return dt.strftime("%B %d, %Y")
    except ValueError:
        # If the parsing fails, return the original string
        return date_string
    
