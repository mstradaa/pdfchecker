MAX_INPUT_LENGTH = 1000


# doc.xref_object() serializes each object to text and is the most expensive
# repeated PyMuPDF call; when several analyzers run on the same document they
# share one sweep through this cache instead of each doing their own.
def build_xref_object_cache(doc):
    """Map each xref number to (object_text, error_message).

    Exactly one of the two tuple members is None: object_text on a read
    error, error_message on success.
    """
    cache = {}
    for xref_num in range(1, doc.xref_length()):
        try:
            cache[xref_num] = (doc.xref_object(xref_num), None)
        except Exception as e:
            cache[xref_num] = (None, str(e))
    return cache


def get_confirmation(prompt: str) -> bool:
    while True:
        try:
            response = input(f"{prompt} (Y/N, Q to quit): ").strip().upper()
            if len(response) > MAX_INPUT_LENGTH:
                print("Error: Input too long. Please try again.")
                continue
            if response == 'Q':
                print("Operation cancelled by user.")
                return False
            if response in ('Y', 'N'):
                return response == 'Y'
            print("Please enter Y, N, or Q.")
        except (EOFError, KeyboardInterrupt):
            print("\nOperation cancelled.")
            return False
