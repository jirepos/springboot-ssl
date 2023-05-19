
var programId = "main";


window.addEventListener("load", function() {
    
    microsoftTeams.initialize();
    let popUpParameters = { 
        url : "/jsp/popup", 
        successCallback: function(result) {
            //TeamsConfiguration.fn.doLoginSuccess(result.psnId, result.userName);
            console.log(result); 
            microsoftTeams.pages.config.registerOnSaveHandler((saveEvent) => {
                const configPromise = microsoftTeams.pages.config.setConfig({
                    websiteUrl: "https://4b24-1-214-255-114.jp.ngrok.io",
                    contentUrl: "https://4b24-1-214-255-114.jp.ngrok.io",
                    entityId: "teamsTestTab1",
                    suggestedDisplayName: "teamsTestTab1"
                });
                configPromise.
                then((result) => {saveEvent.notifySuccess()}).
                catch((error) => {saveEvent.notifyFailure("failure message")});
            });

            microsoftTeams.pages.config.setValidityState(true);

        }
    }
    microsoftTeams.authentication.authenticate(popUpParameters);
}); 


