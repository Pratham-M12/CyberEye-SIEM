// backend/src/services/investigationService.js

import { esClient, ALERTS_INDEX } from "../es/client.js";
import { investigateAlert } from "../llm/investigator.js";

export async function generateInvestigation(alertId){
    const doc = await esClient.get({
        index: ALERTS_INDEX,
        id: alertId
    });
    const alert = {
        id: doc._id,
        ...doc._source
    };
    if(alert.ai_investigation){
        return{
            cached:true,
            investigation:alert.ai_investigation
        };
    }
    const{
        report,
        metadata
    } = await investigateAlert(alert);
    await esClient.update({
        index: ALERTS_INDEX,
        id:alert.id,
        doc:{
            ai_investigation:report,
            ai_metadata:metadata
        }
    });
    return{
        cached:false,
        investigation:report
    };
}