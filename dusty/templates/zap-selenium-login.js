/*
#   Copyright 2019 getcarrier.io
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
*/


var JavaString = Java.type("java.lang.String");
var Base64 = Java.type("java.util.Base64");
var DesiredCapabilities = Java.type("org.openqa.selenium.remote.DesiredCapabilities");
var CapabilityType = Java.type("org.openqa.selenium.remote.CapabilityType");
var HtmlUnitDriver = Java.type("org.openqa.selenium.htmlunit.HtmlUnitDriver");
var TimeUnit = Java.type("java.util.concurrent.TimeUnit");
var HttpRequestHeader = Java.type("org.parosproxy.paros.network.HttpRequestHeader");
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var URI = Java.type("org.apache.commons.httpclient.URI");
var Cookie = Java.type("org.apache.commons.httpclient.Cookie");
var By = Java.type("org.openqa.selenium.By");
var WebDriverWait = Java.type("org.openqa.selenium.support.ui.WebDriverWait");
var ExpectedConditions = Java.type("org.openqa.selenium.support.ui.ExpectedConditions");


/*
    Private functions
*/


function _makeSeleniumSelector(target) {
    if (target.startsWith("id=")) {
        return By.id(target.slice(3));
    }
    if (target.startsWith("name=")) {
        return By.name(target.slice(5));
    }
    if (target.startsWith("link=")) {
        return By.linkText(target.slice(5));
    }
    if (target.startsWith("css=")) {
        return By.cssSelector(target.slice(4));
    }
    if (target.startsWith("//")) {
        return By.xpath(target);
    }
    return By.cssSelector(target);
}


/*
    Public interface
*/


function authenticate(helper, paramsValues, credentials) {
    // Create HtmlUnit driver
    var capabilities = new DesiredCapabilities();
    capabilities.setCapability(CapabilityType.BROWSER_NAME, "htmlunit");
    var driver = new HtmlUnitDriver(capabilities);
    // Enable JS
    driver.setJavascriptEnabled(true);
    // Disable JS errors
    var webClientField = driver.getClass().getDeclaredField("webClient");
    webClientField.setAccessible(true);
    var webClient = webClientField.get(driver);
    webClient.getOptions().setThrowExceptionOnScriptError(false);
    // Set options, such as timeout
    driver.manage().window().maximize();
    driver.manage().timeouts().implicitlyWait(15, TimeUnit.SECONDS);
    // Decode authentication script
    var auth_script = JSON.parse(
        new JavaString(
            Base64.getDecoder().decode(
                paramsValues.get("Script")
            )
        )
    );
    // Command interpreter
    var interpreter = {
        "open": function(driver, target, value) {
            driver.get(target);
        },
        "waitForElementPresent": function(driver, target, value) {
            var selector = _makeSeleniumSelector(target);
            var wait = new WebDriverWait(driver, 15);
            wait.until(ExpectedConditions.presenceOfElementLocated(selector));
        },
        "type": function(driver, target, value) {
            var selector = _makeSeleniumSelector(target);
            var element = driver.findElement(selector);
            element.sendKeys(value);
        },
        "click": function(driver, target, value) {
            var selector = _makeSeleniumSelector(target);
            var element = driver.findElement(selector);
            element.click();
        },
        "clickAndWait": function(driver, target, value) {
            var selector = _makeSeleniumSelector(target);
            var element = driver.findElement(selector);
            element.click();
            var wait = new WebDriverWait(driver, 15);
            wait.until(ExpectedConditions.stalenessOf(element));
        }
    };
    // Interpret authentication script
    auth_script.forEach(function(item) {
        command = item.command;
        target = item.target;
        value = item.value
        value = value.replace(/%Username%/g, credentials.getParam("Username"));
        value = value.replace(/%Password%/g, credentials.getParam("Password"));
        interpreter[command](driver, target, value);
    });
    print("=AUTH=> Final URL: " + driver.getCurrentUrl()); // TODO: Check final URL?
    // Make final request via ZAP
    driver.manage().getCookies().forEach(function(cookie) {
        helper.getCorrespondingHttpState().addCookie(new Cookie(
            cookie.getDomain(),
            cookie.getName(),
            cookie.getValue(),
            cookie.getPath(),
            cookie.getExpiry(),
            cookie.isSecure()
        ));
    });
    msg = helper.prepareMessage();
    msg.setRequestHeader(new HttpRequestHeader(HttpRequestHeader.GET, new URI(driver.getCurrentUrl(), false), HttpHeader.HTTP11));
    msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
    helper.sendAndReceive(msg, true);
    return msg;
}


function getRequiredParamsNames(){
    return ["Script"];
}


function getOptionalParamsNames(){
    return [];
}


function getCredentialsParamsNames(){
    return ["Username", "Password"];
}
