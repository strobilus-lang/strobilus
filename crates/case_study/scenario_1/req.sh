#!/bin/bash

URL="http://127.0.0.1:3000/authorize"

# Example payload (edit as needed)
read -r -d '' PAYLOAD <<EOF
{
  "principal": "User::\"Max\"",
  "action": "Action::\"read\"",
  "resource": "Document::\"file.docx\"",
  "context": "{}"
}
EOF

for i in {0..11}; do
    curl -s -X POST "$URL" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD"
done
