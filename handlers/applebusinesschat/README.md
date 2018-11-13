
## Apple Business Chat Testing

A `developer sandbox` is available at [https://icloud.developer.apple.com/businesschat/](https://icloud.developer.apple.com/businesschat/) which allows you to send messages to/from your own device. This `developer sandbox` is *not* connected to the your organization's test or production Apple Business Chat account. It is a simple one to one conversation between you and the web console.

This is helpful for crafting json payloads to send to apple's chat service, and looking at what a user might respond with, particularly for complex objects like `List Picker`.

You can see real payloads sent by your phone by inspecting the network traffic when it comes in and looking at the response `/zone?remapEnums=true...`, and property `zones["0"].records["0"].fields.payload`


## Rapidpro config

- Create a new Channel `AC` in RapidPro for the config settings
```bash
business_id # apple business id
csp_id # Apple CSP ID
secret # Apple Secret Key

```