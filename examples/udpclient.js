import dgram from "dgram";
const client = dgram.createSocket("udp4");
client.on("error", err => { console.log(err); client.close(); });
client.on("listening", () => console.log("listening on " + client.address().address + ":" + client.address().port));
client.on("message", (msg, info) => {
  console.log(`recieved "${msg}" from ${info.address}:${info.port}`);
  // client.close();
});
client.bind(34029);
client.send(Buffer.from("hi!!!!!!!"), 30000, "localhost");

