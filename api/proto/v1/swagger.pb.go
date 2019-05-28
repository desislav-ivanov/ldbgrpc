package v1 

// Code generated by scripts/swagger-generate.go. DO NOT EDIT.
const (
swagger = `{
  "swagger": "2.0",
  "info": {
    "title": "service.proto",
    "version": "version not set"
  },
  "schemes": [
    "http",
    "https"
  ],
  "consumes": [
    "application/json"
  ],
  "produces": [
    "application/json"
  ],
  "paths": {
    "/v1/cache/Delete": {
      "post": {
        "operationId": "Delete",
        "responses": {
          "200": {
            "description": "A successful response.",
            "schema": {
              "$ref": "#/definitions/v1Status"
            }
          }
        },
        "parameters": [
          {
            "name": "body",
            "description": " (streaming inputs)",
            "in": "body",
            "required": true,
            "schema": {
              "$ref": "#/definitions/v1SearchKey"
            }
          }
        ],
        "tags": [
          "Cache"
        ]
      }
    },
    "/v1/cache/Get": {
      "post": {
        "operationId": "Get",
        "responses": {
          "200": {
            "description": "A successful response.",
            "schema": {
              "$ref": "#/definitions/v1Payload"
            }
          }
        },
        "parameters": [
          {
            "name": "body",
            "in": "body",
            "required": true,
            "schema": {
              "$ref": "#/definitions/v1SearchKey"
            }
          }
        ],
        "tags": [
          "Cache"
        ]
      }
    },
    "/v1/cache/GetAll": {
      "post": {
        "operationId": "GetAll",
        "responses": {
          "200": {
            "description": "A successful response.(streaming responses)",
            "schema": {
              "$ref": "#/x-stream-definitions/v1Payload"
            }
          }
        },
        "parameters": [
          {
            "name": "body",
            "in": "body",
            "required": true,
            "schema": {
              "properties": {}
            }
          }
        ],
        "tags": [
          "Cache"
        ]
      }
    },
    "/v1/cache/GetMany": {
      "post": {
        "operationId": "GetMany",
        "responses": {
          "200": {
            "description": "A successful response.(streaming responses)",
            "schema": {
              "$ref": "#/x-stream-definitions/v1Payload"
            }
          }
        },
        "parameters": [
          {
            "name": "body",
            "description": " (streaming inputs)",
            "in": "body",
            "required": true,
            "schema": {
              "$ref": "#/definitions/v1SearchKey"
            }
          }
        ],
        "tags": [
          "Cache"
        ]
      }
    },
    "/v1/cache/Put": {
      "post": {
        "operationId": "Put",
        "responses": {
          "200": {
            "description": "A successful response.",
            "schema": {
              "$ref": "#/definitions/v1Status"
            }
          }
        },
        "parameters": [
          {
            "name": "body",
            "description": " (streaming inputs)",
            "in": "body",
            "required": true,
            "schema": {
              "$ref": "#/definitions/v1Payload"
            }
          }
        ],
        "tags": [
          "Cache"
        ]
      }
    }
  },
  "definitions": {
    "StatusResponse": {
      "type": "string",
      "enum": [
        "OK",
        "Error"
      ],
      "default": "OK"
    },
    "protobufAny": {
      "type": "object",
      "properties": {
        "type_url": {
          "type": "string"
        },
        "value": {
          "type": "string",
          "format": "byte"
        }
      }
    },
    "runtimeStreamError": {
      "type": "object",
      "properties": {
        "grpc_code": {
          "type": "integer",
          "format": "int32"
        },
        "http_code": {
          "type": "integer",
          "format": "int32"
        },
        "message": {
          "type": "string"
        },
        "http_status": {
          "type": "string"
        },
        "details": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/protobufAny"
          }
        }
      }
    },
    "v1Payload": {
      "type": "object",
      "properties": {
        "key": {
          "type": "string",
          "format": "byte"
        },
        "value": {
          "type": "string",
          "format": "byte"
        }
      }
    },
    "v1SearchKey": {
      "type": "object",
      "properties": {
        "key": {
          "type": "string",
          "format": "byte"
        }
      }
    },
    "v1Status": {
      "type": "object",
      "properties": {
        "code": {
          "$ref": "#/definitions/StatusResponse"
        }
      }
    }
  },
  "x-stream-definitions": {
    "v1Payload": {
      "type": "object",
      "properties": {
        "result": {
          "$ref": "#/definitions/v1Payload"
        },
        "error": {
          "$ref": "#/definitions/runtimeStreamError"
        }
      },
      "title": "Stream result of v1Payload"
    }
  }
}
`
)
