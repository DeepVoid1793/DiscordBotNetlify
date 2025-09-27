const nacl = require("tweetnacl");
const { Buffer } = require("buffer");

const PUBLIC_KEY = "Yc8c034dd67aecf40f8f79ae58bfe91e343f263289aa06fee924c59e4dec0662b";

exports.handler = async (event) => {
  if (!verifyDiscordRequest(event)) {
    return { statusCode: 401, body: "Invalid request signature" };
  }

  const interaction = JSON.parse(event.body);

  // Discord ping check
  if (interaction.type === 1) {
    return {
      statusCode: 200,
      body: JSON.stringify({ type: 1 }),
    };
  }

  // Slash command: /ping
  if (interaction.type === 2 && interaction.data.name === "ping") {
    return {
      statusCode: 200,
      body: JSON.stringify({
        type: 4,
        data: {
          content: "🏓 Pong from Netlify!",
        },
      }),
    };
  }

  return { statusCode: 400, body: "Unknown interaction" };
};

function verifyDiscordRequest(event) {
  const signature = event.headers["x-signature-ed25519"];
  const timestamp = event.headers["x-signature-timestamp"];
  const body = event.body;

  return nacl.sign.detached.verify(
    Buffer.from(timestamp + body),
    Buffer.from(signature, "hex"),
    Buffer.from(PUBLIC_KEY, "hex")
  );
}
