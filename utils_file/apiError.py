# Import your ApiError class
class ApiError(Exception):
    def __init__(self, statusCode, message="Something went wrong" ):
        super().__init__(message)
        self.statusCode = statusCode
        self.data = None
        self.message = message
        self.success = False
        

        
