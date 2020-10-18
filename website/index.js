import * as tls_parser from "tls-parser-wasm";

const inputtext = document.getElementById("inputtext");
const outputtext = document.getElementById("outputtext");
const submitbutton = document.getElementById("submit");

function handleChange(e) {
    doIt();
}

function extract_hexes(inputs){
    if (inputs.startsWith("0000 - ")){
        //looks like an openssl hexdump, Let's extract!
        inputs = inputs.replaceAll(/^\d\d\d\d - /mg, ''); //line headers
        inputs = inputs.replaceAll(/   .*$/mg, ''); //line footers
        inputs = inputs.replaceAll(/[ -]/g, '');  //spaces and hyphens
        inputs = inputs.replaceAll(/\n/g, '');  //make it a single line
        alert(inputs);
    }
    return inputs;
}

function doIt(){
    var pretty = JSON.stringify(
        JSON.parse(tls_parser.parse_string(extract_hexes(inputtext.value))),
        null,
        2);

    outputtext.innerHTML = pretty
  }

  /*inputtext.addEventListener(
      "change",
      e => handleChange(e)
  );
*/
  submitbutton.addEventListener(
      "click",
      e => handleChange(e)
  );

