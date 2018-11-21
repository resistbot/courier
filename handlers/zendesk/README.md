
# Zendesk Config

A zendesk trigger needs to be configured with the following settings:

## Conditions
- Meet ALL of the following conditions
```
Current user IS (end user)
```
## Action
- Notify Target `https://<your courier url>/c/<your integration uuid>/receive`

- JSON: ```json
{
"id" : "{{ticket.id}}",
"title": "{{ticket.title}}",
"comment" : "{{ticket.latest_comment}}",
"requester_id" : "{{ticket.requester.id}}",
"requester_name": "{{ticket.requester.name}}",
"attachments": [
    {% for attachment in ticket.latest_comment.attachments %}
    {
        "filename": "{{attachment.filename}}",
        "url": "{{attachment.url}}"
    }
    {%if forloop.index != forloop.length%},{% endif %}
    {% endfor %}
]
}
```
