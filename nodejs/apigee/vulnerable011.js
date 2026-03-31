/*
   Apigee JavaScript Callout: Múltiples Vulnerabilidades en el Gateway
   Este script se ejecutaría dentro de una política <Javascript> en el flujo de un API Proxy.
   Utiliza el modelo de objetos nativo de Apigee (context, request, httpClient).
*/


/*
<ServiceCallout async="false" continueOnError="false" enabled="true" name="SSRF-Vulnerable-Callout">
    <DisplayName>Fetch Avatar</DisplayName>
    <Request clearPayload="true" variable="myRequest">
        <Set>
            <Verb>GET</Verb>
        </Set>
    </Request>
    <Response>calloutResponse</Response>
    <HTTPTargetConnection>
        <URL>{request.queryparam.avatarUrl}</URL> 
    </HTTPTargetConnection>
</ServiceCallout>

*/





/*
<VerifyJWT name="Verify-JWT-Insecure">
    <Algorithm>HS256</Algorithm>
    <SecretKey>
        <Value ref="private.secretkey"/>
    </SecretKey>
    <IgnoreUnresolvedVariables>true</IgnoreUnresolvedVariables>
    <TimeAllowance>999999999</TimeAllowance>
</VerifyJWT>

*/



var path = context.getVariable("proxy.pathsuffix");
var verb = context.getVariable("request.verb");
var WEBHOOK_SECRET = "secure_secret_webhook_key_12345";

try {
    // 1. SSRF (Server-Side Request Forgery)
    if (path === "/api/fetch" && verb === "POST") {
        var body = JSON.parse(context.getVariable("request.content"));
        var targetUrl = body.url; // Entrada del usuario no validada
        
        // VULNERABLE: El Gateway hace una petición a la URL inyectada 
        // (Podría ser la red interna de GCP/AWS donde está hosteado Apigee)
        var ssrfRequest = new Request(targetUrl, "GET");
        var exchange = httpClient.send(ssrfRequest);
        exchange.waitForComplete();
        
        context.setVariable("response.content", exchange.getResponse().content);
        context.setVariable("response.status.code", 200);
    }

    // 2. HTTP Parameter Pollution (HPP) y Type Confusion
    else if (path === "/api/transfer" && verb === "GET") {
        // En Apigee, si pasas ?account=1&account=2, puedes acceder a todos con request.queryparam.account.values
        // o al primero con request.queryparam.account
        var accountCount = context.getVariable("request.queryparam.account.values.count");
        var accountStr = context.getVariable("request.queryparam.account");

        // VULNERABLE: Lógica defectuosa al manejar múltiples parámetros.
        // Si el WAF u otra política validó solo el primer parámetro, usar el array completo
        // o el último valor en el backend puede causar un bypass.
        if (accountStr === "0000") {
             context.setVariable("response.status.code", 403);
             context.setVariable("response.content", "Invalid Transfer");
        } else {
             // Redirigir el tráfico mutando el target (Target Routing Manipulation)
             var accountsArray = context.getVariable("request.queryparam.account.values");
             // Usamos el último parámetro suministrado evadiendo la validación del primero
             var targetAccount = accountCount > 1 ? accountsArray[accountCount - 1] : accountStr;
             
             context.setVariable("target.url", "https://backend-banco.internal/transfer?acc=" + targetAccount);
             context.setVariable("response.content", "Routing to backend...");
        }
    }

    // 3. JWT y Verificación de Firmas Inseguras (Hecho a mano en JS en lugar de usar políticas nativas)
    else if (path === "/api/webhooks/payment" && verb === "POST") {
        var payload = context.getVariable("request.content");
        var signatureProvided = context.getVariable("request.header.x-signature");

        // Utilizando la librería de crypto básica de Apigee (CryptoJS)
        var expectedSignature = crypto.HMAC(crypto.SHA256, payload, WEBHOOK_SECRET).toString();

        // VULNERABLE: Comparación directa propensa a ataques de tiempo (Timing Attacks)
        if (signatureProvided === expectedSignature) {
            context.setVariable("response.content", '{"status": "Pay OK"}');
            context.setVariable("response.status.code", 200);
        } else {
            context.setVariable("response.status.code", 403);
            context.setVariable("response.content", "Error: Invalid Sign");
        }
    }

    // 4. ReDoS (Regular Expression Denial of Service en el Gateway)
    else if (path === "/api/validate-format" && verb === "POST") {
        var body = JSON.parse(context.getVariable("request.content"));
        var input = body.input;
        var emailRegex = /^([a-zA-Z0-9]+\s?)*$/;

        // VULNERABLE: Si se envía "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!", el hilo del Message Processor 
        // de Apigee se bloqueará consumiendo CPU, provocando un DoS en el API Gateway.
        var isValid = emailRegex.test(input);
        
        context.setVariable("response.content", '{"isValid": ' + isValid + '}');
    }

    // 5. Modificación Insegura de Cabeceras (Header Injection)
    else if (path === "/api/login" && verb === "POST") {
        var body = JSON.parse(context.getVariable("request.content"));
        var role = body.role; // Payload: "admin\r\nInjected-Header: true"

        // VULNERABLE: No sanitizar los inputs que se inyectan en cabeceras HTTP hacia el backend (CRLF Injection)
        context.setVariable("request.header.X-User-Role", role);
        context.setVariable("response.content", "Forwarding login to backend...");
    }

    else {
        context.setVariable("response.status.code", 404);
        context.setVariable("response.content", "Not Found");
    }

} catch (err) {
    // Fuga de información: Devolver la traza del error exacta al cliente
    context.setVariable("response.status.code", 500);
    context.setVariable("response.content", "Gateway Error: " + err.toString());
}
