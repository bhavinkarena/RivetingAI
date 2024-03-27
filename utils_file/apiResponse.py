class ApiResponse:
    def __init__(self, statusCode, data, message="Success"):
        self.statusCode = statusCode
        self.data = data
        self.message = message
        self.success = statusCode < 400
