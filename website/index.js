import * as tls_parser from "tls-parser-wasm";

const inputtext = document.getElementById("inputtext");
const outputtext = document.getElementById("outputtext");
const submitbutton = document.getElementById("submit");

function handleChange(e) {
    doIt();
}

function doIt(){
    var pretty = JSON.stringify(
        JSON.parse(tls_parser.parse_string(inputtext.value)),
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

