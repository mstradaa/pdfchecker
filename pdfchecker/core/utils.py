MAX_INPUT_LENGTH = 1000

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
