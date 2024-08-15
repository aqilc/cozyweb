import dgram from "dgram";
const server = dgram.createSocket("udp4");
server.on("error", err => { console.log(err); server.close(); });
server.on("listening", () => console.log("listening on " + server.address().address + ":" + server.address().port));
server.on("message", (msg, info) => {
  console.log(`recieved "${msg}" from ${info.address}:${info.port}`);
  // server.close();
});
server.bind(30000);
