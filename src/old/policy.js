const output = {};

const err = msg => {
    output.error = true;
    output.message = msg;
};

if (["get", "delete"].includes(input.api_method)) {
    const body = input.api_method === "get" ? input.request_body.Get : input.request_body.Delete;
    if (!body.keys.every(key => key.startsWith("_acme-challenge") && key.endsWith(".:TXT"))) {
        err("Invalid key");
    }
} else if (input.api_method === "set") {
    if (
        !input.request_body.Set.records.every(
            record => record.name.startsWith("_acme-challenge") && record.name.endsWith(".:TXT")
        )
    ) {
        err("Invalid key");
    }
} else {
    err(`API method '${input.api_method}' not allowed`);
}

if (output.error === undefined) {
    output.error = false;
    output.message = "Success";
}
