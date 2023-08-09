import org.junit.jupiter.api.Test;
import poort8.ishare.core.Authorisation;

public class AuthorisationTest {
    @Test void VerifyAccessReturnsTrue() {
        String token = "eyJ4NWMiOlsiTUlJRWx6Q0NBbitnQXdJQkFnSUlKWGdMMHBKK0lvQXdEUVlKS29aSWh2Y05BUUVMQlFBd1NERVpNQmNHQTFVRUF3d1FhVk5JUVZKRlZHVnpkRU5CWDFSTVV6RU5NQXNHQTFVRUN3d0VWR1Z6ZERFUE1BMEdBMVVFQ2d3R2FWTklRVkpGTVFzd0NRWURWUVFHRXdKT1REQWVGdzB4T1RBeU1UVXhNVFEyTWpaYUZ3MHlNVEF5TVRReE1UUTJNalphTUZneEt6QXBCZ05WQkFNTUltbFRTRUZTUlNCVVpYTjBJRUYxZEdodmNtbDZZWFJwYjI0Z1VtVm5hWE4wY25reEhEQWFCZ05WQkFVVEUwVlZMa1ZQVWtrdVRrd3dNREF3TURBd01EUXhDekFKQmdOVkJBWVRBazVNTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF4KzlvQUxqam9sMitMeVl3TnlSekpqZ0IyWlIxaUtQVzRiMHRmL041ZnkyZUFPS3dFTElOTkRxNlU5M00vdlVxWXBkVlVqV1VVZjQrZ3ZxTW00UGUwdUZhWDlXTEJ6WWQvMGNQcUlmd3l5ZDgzeGhlMk1MeEExSHpPUjJOQUQ1b0oxR1RoRXpWRzQybVlGc0hyVEJRaXcrUHNrNXBWM1B1QlNXc0Q2SUxNOUlBU3BpZlcwSmR0dDdDQU5VeVkvc3l2dmx2ejlKdXhQbjNsc01pT25tLys1ZnpRMFZTS1ZtTEVjUWgyeTBmd0FySWtiQkYxQTNaeG5LWHJLUUVZTllIZmlqVk11VkZVOVQ3QjVTVmFsUVJDUjY0ZUdNeTA5Rm53ZGJWOEVUZTMwYnhsamx6QjAzeWhNbFllS3BnY3ZkRlBHN1BkNzZIKyszS3JDdnJxS0FuZFFJREFRQUJvM1V3Y3pBTUJnTlZIUk1CQWY4RUFqQUFNQjhHQTFVZEl3UVlNQmFBRkJZODV5RHAxcFR2SCtXaThiajh2dXJmTERlQk1CTUdBMVVkSlFRTU1Bb0dDQ3NHQVFVRkJ3TUJNQjBHQTFVZERnUVdCQlNwcmZuMnVvWUNTRC9rMUhURit6YnpPdU9UN3pBT0JnTlZIUThCQWY4RUJBTUNCYUF3RFFZSktvWklodmNOQVFFTEJRQURnZ0lCQUxxaURza0c3RXczelloVTJSUXBOUU50MEtocy9tZDFmUDVMYzFxTUQvVlhVSWFpaC9DM3daRVF2UjhoaFFYTGVNNzlxSDNIeDhUSjJ0eDBubUU1N1FnV3pVdjBINEMrbGYyak93eExyZytwVksyVzRxUmEzNmZiSkdMd2FONW9CVnJEejhuT0F2RXFZUVZ0ckdsVlVNbGFYNkF6dVpJT2J1cW9RNHdQNTdrV1ZHdTdaUitYdzlxYk5qK2RNNjEzOUxGSGV4MHlDeXg5NHF1Q2ZaM254eEVnN3ZjaTUvS3ErMEFSZjJxbG1RdlozSm14dXdEMEZTQS9TVi9QWkhLcFk1NVl4M0hFR01oeVVyT0Z3OVY2d015TllUTWIyUmVRUzJyQ0h1UXhTcGg0eVErZTNEc0dkcWxTM01JYS9hYzN6SXRCR2RDVXZGQ092cHdBOUpxNHJNV3Q4Ulh2ZUNQYkNuM0ZteUsrSFpTV001M0VCM1pFUk9lK0FJMWN5NnhhbGxac21iRUY1MHFXeVh3UEJ6WExpNU1ZcmNXUmZYOFI0RUxWYnRxTWR2YWIyN2JtR0Z4UVBuTmIxOElSd05BNjVrMkFrbVc1Tjd0dXFoZGNaSnl4Uk84MDJUTDJ0V3dxRStzQjdIQS9ReXRZb0wxOUticnUvbHg2a2FwVEdrWldzSHhERVBMOUNIaDZNS3VUY3dFMWcwbkJ2OUwwbGhGQWFkWmU2QlpEbWdJak1tbW54aGszc1lLTW5Lc2Yrc083WlUrOSt3dER6U3E0UTNMUlJmNUpJQWdRZU9rMjBjejRjdkVKbEgyMHUrL3hEeGpoL1BWVW4vS1h0UVJRY2ZMNk1OV2JoSExUTmpPenBLZGw2OGJCMXVseDF3MHJMUStLRTRWR1pYMFB1MTM2IiwiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0RFFwTlNVbEdZMVJEUTBFeGJXZEJkMGxDUVdkSlNWTkdVa3AzUjBGQmVXcFZkMFJSV1VwTGIxcEphSFpqVGtGUlJVeENVVUYzVWtSRlZrMUNUVWRCTVZWRkRRcEJkM2ROWVZaT1NWRldTa1pXUjFaNlpFVk9RazFSTUhkRGQxbEVWbEZSVEVSQlVsVmFXRTR3VFZFNGQwUlJXVVJXVVZGTFJFRmFjRlV3YUVKVmExVjREUXBEZWtGS1FtZE9Wa0pCV1ZSQmF6Vk5UVUkwV0VSVVJUUk5SR041VFhwRk1VMVVVWGhOTVc5WVJGUkplazFFWTNsTmFrVXhUVlJSZUUweGIzZFRSRVZhRFFwTlFtTkhRVEZWUlVGM2QxRmhWazVKVVZaS1JsWkhWbnBrUlU1Q1dERlNUVlY2UlU1TlFYTkhRVEZWUlVOM2QwVldSMVo2WkVSRlVFMUJNRWRCTVZWRkRRcERaM2RIWVZaT1NWRldTa1pOVVhOM1ExRlpSRlpSVVVkRmQwcFBWRVJEUTBGcFNYZEVVVmxLUzI5YVNXaDJZMDVCVVVWQ1FsRkJSR2RuU1ZCQlJFTkREUXBCWjI5RFoyZEpRa0ZRZFdWU1dGVkhVMVZuZFRkeGNFRlhTbXBCVmtnNWVqTXhPVmh1ZFVac1pWWmxUeTlZZUdKS05sVTBhWGhZVWt0MlZ6aDJTMVJXRFFveFpGSmpabEZsUTNGWWF6ZDFZUzlhYzNGT2NuRTRPVVY0T1RWaU1HNXhSMVYyTVU1dlN6SlVPSGxGUVd0UmVubDZXVnB3VnpSak1sbE5RMk5uTldGdERRcFNkME5tV1dGb1NIUktiVmhLVjNGU1JXVjJUVFZyU205UFlXTkxTQzlIVldKelpXMVVPVFJDTUV0WVUwNVJOa2xYWTBwNWFuQjFZVzlFY0dJMlYyUTVEUW8zVkRKc2RWQXhTVkUxWjJ0bWQxVXpPRU5hU2t0V2EySlpNMlZLYTB4c1QzZDNkRVp6UmxCUU1rMDBaamgxTkRjNVQydE5WWEkxTDIwcmVHNDNNMHBoRFFwYVUwcEdUMGgyU1U0MlJFWndRV3h6TW1GNE4wSm9WVk5zWWt0Tk0xbEZkVTVpTUU4MGIwODFlVzVFUmtoMmJXeHNjRFpPZFRCR01saHZNRUoxTUZBdkRRcDFjV0l2TURoWWRsWlhibVUzZDJOM1YxcFNPU3RrTnpoeEswOXNaa012YlN0M1FYZEJjVzFSU0VWeU9HaEtUblpTTmxNdk9EUklRV3BWWkUxNVIyTlpEUXBVZG05Mk1IUmlNRnAzTDBGTGQwUm5PRkJET1ZWR1VsbGlNR05DY2pBckwwZG1aMjFLVURWUlRVRm1USEZyV0cxYWQxbFJVMW94Um1GdFRteEtiRzE0RFFvd2MxbGFVVk5oZFdSSE1DdFlhMk01T1RFclduY3ZlRGgxVjFwcE9YRlJXbVZDVDJSM2Jra3llR1l2U0VwWVNFcHpZVnBtUkhaVWNEVnBPR2xXVURjMURRb3hjbWhwYm5kTWFUSmtXbTV0VTNOUk9UWm5kblJVVVVKdk5FbzFRWFpHSzNNNVNXd3JWSFZyWlV4MGJFdEJRbUZ2VFhkNk9IZFpRa051Wmt0MlZYUnJEUXB3TjBwVk5XbHFhbGxHWVhGUmMwWlNNMUp3VDBoWVkwZ3ZjM0JhVkZsSWRWTnpNVTl3U0ZaaWNqQXZZMFowVjFwd2RqUjBVMUZyYkZCeFEycGtaRk5CRFFwVFNEbHJNMDlDUVdoNFpXNTVXRXhyYmpsVk9VRkJTVE0wY0ZwaVJsWXJiV3R6UjBkeVRqZDFhMnMwYjJKVGRFazNlaTgxUVdkTlFrRkJSMnBaZWtKb0RRcE5RVGhIUVRGVlpFVjNSVUl2ZDFGR1RVRk5Ra0ZtT0hkSWQxbEVWbEl3YWtKQ1ozZEdiMEZWY21FelMzTlVibFZXYmxrNFMxaG5iREJTYVdsUlFuUnZEUXBMUlhkM1NGRlpSRlpTTUU5Q1FsbEZSa0paT0RWNVJIQXhjRlIyU0N0WGFUaGlhamgyZFhKbVRFUmxRazFCTkVkQk1WVmtSSGRGUWk5M1VVVkJkMGxDRFFwb2FrRk9RbWRyY1docmFVYzVkekJDUVZGelJrRkJUME5CWjBWQlpVbEtkekZ1Ym05UGNuTmhiWFZsVnpSaldsQk1lbkp1ZFVoVFJYWjJNVk5GVERGaURRcG1RalpHTnpOaGJtMTRZbkU1SzA5WlZ6WnhiMnBvZUhadmNraFVSbnB2VVhsdWMxQnRZbk52TjNRMFlqTklRWFJYWVU5c2NETkVTMXBWVkhCNlQyeE1EUXB1VVRsbmMwUkVaa1JXVTBwelNqVnFlR2RzUkVaYWJUQkJNRGRNWkRORGVGcG9ibnBYWmpsQk1GRm5UbkZPTldoRFkwOXpjbXcwZFVSTmRscDZLMDA1RFFwclRDOXBhM05EZURSWU1ITnZNazlUYlRGUllXdHlZVUZTTTNWdFVHTXliMjlCWVdOUWMwRldRMnhzWld0WVJrbzVSRVpxU2pWVmRpdHlaemhhUzBoSURRcE1SM0pRTVRsdkwwRnpXRXBaY0V0UUwzUjBhelYwUW5WQk5FcENNakJoVTJoaVkwTTFNemx5UVN0Ull5dHJSRWg1VW01TU1HRktlVkpaWlVKbldURnBEUXBCZEhWNldIcE5UMnMxTTFoV0syRktiMmRFY0ROblJqY3pjekZqTVZsNVNWSklkRGR2WmxGSEx6QmFiSGRqTHpReFEzaFBSQ3RzZVhwSE16UlNhMmRKRFFwVlR6WlZabXBwUjBOR1VHMWFVVEpJYTNCTGVYRk1hV1p5WVZKa2NYSklXRTlvYjFaa04waHBaRmxKYVdodVdrdEVhMHhwTVdObVpXOHliWG80ZEZkcERRcFZla0VyWkZCamFHRkpSV3h3VVVwUVZHcFRZa3hxUmpKSk1UbFJlVUk0Wm5WUVlYcFFaazVKYWtoeVdHRkxiR0ZUTTJ4MVMyTkdhWEZQV1dkamQxZG1EUXBrV20xRWVuaEpWVFpRV1RKaWVuZ3ZVMFJOYjFVeU5ISkJWbE4xUjBGWlFrbEJiSGRtTW5CNGJYUk1ZMkpOUVRaaVdYSTBkSEp0VVdaaVNuSk5PR1k0RFFwS1dtZEhVVzlKZEhKd2VuSkxha0pLTW1kR1VuUXJNRFkxVGsxVVRtdENOWEozT0ZoeU5UWnFOV1JxYTNGQ01DOXhTRWxqUmpKVWFWa3ZheTg0TVZKdERRcFVRMWw0Y2xaSWVrMHhZM3BvV0VoWVdYcDJibVF5U213eGQwcFllV0ZqVjJ3M1JtbFFZV2RuZHpCWlVXbGtWMGhIVFdSSmRFVjFSQzg0VTFocFExaHNEUW94VDBsMmRtbGpQUTBLTFMwdExTMUZUa1FnUTBWU1ZFbEdTVU5CVkVVdExTMHRMUTBLIiwiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0RFFwTlNVbEdZbFJEUTBFeFYyZEJkMGxDUVdkSlNVaHFhbVpVZFZOcVJtcE5kMFJSV1VwTGIxcEphSFpqVGtGUlJVeENVVUYzVWtSRlZrMUNUVWRCTVZWRkRRcEJkM2ROWVZaT1NWRldTa1pXUjFaNlpFVk9RazFSTUhkRGQxbEVWbEZSVEVSQlVsVmFXRTR3VFZFNGQwUlJXVVJXVVZGTFJFRmFjRlV3YUVKVmExVjREUXBEZWtGS1FtZE9Wa0pCV1ZSQmF6Vk5UVUkwV0VSVVJUUk5SR041VFhwRk1VMUVWWGhOTVc5WVJGUkpORTFFWTNsTlJFVXhUVVJWZUUweGIzZFNSRVZXRFFwTlFrMUhRVEZWUlVGM2QwMWhWazVKVVZaS1JsWkhWbnBrUlU1Q1RWRXdkME4zV1VSV1VWRk1SRUZTVlZwWVRqQk5VVGgzUkZGWlJGWlJVVXRFUVZwd0RRcFZNR2hDVld0VmVFTjZRVXBDWjA1V1FrRlpWRUZyTlUxTlNVbERTV3BCVGtKbmEzRm9hMmxIT1hjd1FrRlJSVVpCUVU5RFFXYzRRVTFKU1VORFowdEREUXBCWjBWQk5FaEpVVEpsUjFoVFVEQmljV2RQY3paSlluSjRWSGN2TUhVMldIbFNhVFZJTDFvcmFqaG9VSHBHWlZNdmJqZFZZMFJ6S3pRNFIxbFRaMFZPRFFveFkwbEVRa0ZIVjJwdWQwNU5OblUwVW5CUmFVYzRlR3czV1hScVYzbHRkMHR0TkVoWWRFeEJVWEYwTnpKaGNsa3pOMUJUUmpNd1dHazJWbEJDWVc1MERRcFFWR1JoWVNzNWVrTlZPRU41Um01RldqSm1TMVJyTVZOMVp6TTJaelpHTms5cVpHZERRMGRyYW1Sd2NFdFdlVTVKYkRWUFZ5dHJha1p4TWtFNVIzWjBEUXBDVWtkRmQxSXlaWFJ2ZEV0MGMwbElTUzluTkdOWVQwWmFhblJEUTNSUWIwVnRhbEUyTm1aVGQyRTNRV3B2YkhCQ1lqSlFZM056UTFad1lqVmpObk5CRFFwbWNESXdTazV1T0RSclJGRkZiMGhxWlc5NVRrRnhZM1JDUlVselVscEdOR3R3Vkc0MFdXaFRXSEV3VkVndmExSjBSVVZtVGtWdGVreEZUMU5oUkZkUURRcDVURGh4U2twd2VERmhVRUY1WlRCbWEwZG1TbWsxTVdOSFVuSkdlR1kzYW1aT09UbFVhbVJtTTNsNGQzUlVMM2xSY1hWWFRIQTJWa3hrY1dwS1RHczVEUXBpZEVkckswSnBVemxwVm5SM05ERkZZeko1YzFndk0yY3dlR1ZXVmtaSGRIbERkMEZEVjNCNVNYZ3JVVzA0TUV0cVZsaHJXVVI0YUVkcFRGRnFVVWw2RFFwV2IyeFFSVlpWUkVGYWJuY3JURU50WnpOUFdUbEplVEJRV0ZSV01IZ3pRMHRJVFN0RE0zVnJXbGRyVXpGa00wTlRaMFJXYkRFclkzQklTbFEwYlRabURRcExibTVqVHpjM2VWWlBNSGx5VnpVeU1UaFZSMkZaUVV4UGFEaFFTRzkzTXpabE9XTkNNbU13WWxReVpERkRTRkpsYTFOc05DdENlQ3Q0VVUxSGQzTlFEUXA1ZG1WSFozQnJTR2xrV25SWlVrUlFORVV2U0hoT1Mza3JkMlpDZVZGbFUzVTBXV05WWXpoRlNIaDVPWEY2ZUdGbE1qaFJabHB1TjNNME4xWXZVR3BCRFFwck1HUk1XbmxSUkc5dVJUbFJNVEJQYTAxV01UVkVjRGxRVjBkbFExRktjbWsxU21SUGJuSXJhVVE0UkdSSWMwTkJkMFZCUVdGT2FrMUhSWGRFZDFsRURRcFdVakJVUVZGSUwwSkJWWGRCZDBWQ0wzcEJaa0puVGxaSVUwMUZSMFJCVjJkQ1UzUnlZM0Y0VDJSU1YyUnFkM0JsUTFoU1IwdEtRVWN5WjI5VVJFRmtEUXBDWjA1V1NGRTBSVVpuVVZWeVlUTkxjMVJ1VlZadVdUaExXR2RzTUZKcGFWRkNkRzlMUlhkM1JHZFpSRlpTTUZCQlVVZ3ZRa0ZSUkVGblIwZE5RVEJIRFFwRFUzRkhVMGxpTTBSUlJVSkRkMVZCUVRSSlEwRlJRa05IV1U1c0x6RklSbGRXYUVSdlVHMXJjRlp4YlRNd2NubHhaalprVjNneGNuaFVWekZzYXpsaERRcFdWVTlzVWpsSlVraFFjREY2TDBZdk5HWmlObTFKV0VacVJsbDNOV3hWTW1aaFNGWTViM0EwY2s1MVIzRlNVbE5NYVZGUVZuWlBXSGhFYkhoeFFUWkVEUXB0Y1hwcFVrVjJkSFJITUhWTVdpOUdUM2xqUzFrMU0zQlhSa042UnpKclpYRTJUMGxrT1VwVGNFWnRVVVJQYVVZM1YxTjFhV1pRVEhWM1FVUnJWWGNyRFFwdldsbEhaMWR0WW5kUlR6QnNXSFIzTjFoUGJua3pOMjVNV210WmJEZzVZbEpvU1djdk4yWmlLMWh1WWpnNU1UUlRUWFl3YTBkc2F6RnJRMlY1VERaR0RRcFlaRmhTVkdGaGREVmpPVmhzU25JNWVYcFBWVWxFYmpVMFlsa3hRa3RVTmxsMGFYbEtablpEVG1GMkwwWmlNalIyTldWeE1sbzViVUprV2pjd1EyTTVEUW8xWjFCcWNYRjRUVnBWWjBwdk5UZFpkbWhNWmxoRWQzaGlWMXBYV1VNclYyTlNPRzVJYTFrcmRGcENiRWxwYURKRFdFaHpUMkZ5Tlc5SU5tUnlUV1IwRFFwTlNWcDZNMVZhU2k5RGVFWkhNWFV5TTFWNk1XcENabTB2UldkblpFdG9UMVp1VkRabFpISjFWbTkwWlZkWFEwUkNPVWhrYUhoNk9GSkJWbGx1TldSeERRcFZhbXRxVW5FMFZ6bFJRV1pLZFhOeVVGcEhRbTVrVkRkNVRtRlpMMFpJV1V0SmNTdDFWR0Z5VjJsaWFtUjRkR1JaUTJ4aFZIZFBlR3MxU1hGTFRrWTVEUXBsUTB0aVVHMTRjekZ0YkZweVUweHFUVkZHV1ROVk9WSnJkbnBKS3pOSmJFRkdhMk4wVldWaFluQnJiVmg0Ym5WWFYxTldNa1pLVHpsYWNrOU9UVmQxRFFwMGR5czFOamRRU3pWbmVrMHdSbkZSZG1JM2MwTjRXblZSUkd3MVEzUTJXbGRzZEhNeVdUY3lkRFp3VUdwU1NURTNLMU00S3l0aE1uWlJaSGhDWTA1UkRRb3dlRVl5ZEdwMmVsUjJhVm96UXpWRmNVbGxZWHBYWkdkSldtdHhabGRhYTFNNGRpc3dUVUYyVGxwWksySmllQ3QyVTNkTVQyOUlVVmR5Wmk5UFEwdzNEUXBCVVQwOURRb3RMUzB0TFVWT1JDQkRSVkpVU1VaSlEwRlVSUzB0TFMwdERRbz0iXSwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJFVS5FT1JJLk5MMDAwMDAwMDA0Iiwic3ViIjoiRVUuRU9SSS5OTDAwMDAwMDAwMSIsImp0aSI6ImQ4YTdmZDc0NjU3NTRhNGE5MTE3ZWUyOGY1YjdmYjYwIiwiaWF0IjoxNTkxOTY2MjI0LCJleHAiOjE1OTE5NjYyNTQsImF1ZCI6IkVVLkVPUkkuTkwwMDAwMDAwMDEiLCJkZWxlZ2F0aW9uRXZpZGVuY2UiOnsibm90QmVmb3JlIjoxNTQxMDU4OTM5LCJub3RPbk9yQWZ0ZXIiOjIxNDc0ODM2NDcsInBvbGljeUlzc3VlciI6IkVVLkVPUkkuTkwwMDAwMDAwMDUiLCJ0YXJnZXQiOnsiYWNjZXNzU3ViamVjdCI6IkVVLkVPUkkuTkwwMDAwMDAwMDEifSwicG9saWN5U2V0cyI6W3sibWF4RGVsZWdhdGlvbkRlcHRoIjowLCJ0YXJnZXQiOnsiZW52aXJvbm1lbnQiOnsibGljZW5zZXMiOlsiSVNIQVJFLjAwMDEiXX19LCJwb2xpY2llcyI6W3sidGFyZ2V0Ijp7InJlc291cmNlIjp7InR5cGUiOiJHUzEuQ09OVEFJTkVSIiwiaWRlbnRpZmllcnMiOlsiMTgwNjIxLkNPTlRBSU5FUi1aIl0sImF0dHJpYnV0ZXMiOlsiR1MxLkNPTlRBSU5FUi5BVFRSSUJVVEUuRVRBIiwiR1MxLkNPTlRBSU5FUi5BVFRSSUJVVEUuV0VJR0hUIl19LCJlbnZpcm9ubWVudCI6eyJzZXJ2aWNlUHJvdmlkZXJzIjpbIkVVLkVPUkkuTkwwMDAwMDAwMDMiXX0sImFjdGlvbnMiOlsiSVNIQVJFLlJFQUQiLCJJU0hBUkUuQ1JFQVRFIiwiSVNIQVJFLlVQREFURSIsIklTSEFSRS5ERUxFVEUiXX0sInJ1bGVzIjpbeyJlZmZlY3QiOiJQZXJtaXQifV19XX1dfX0.mdnNbj4b7u6YmCbzxk0Sn2wvceo9dG_7mikMcpxUG4JLf3Yd4dovUL10y_OaqLmSgxe7yYtacV5PPeOvZX4DFXv-aMxF_ueBTgqm1A8GCMfxd5gBO848tUmp0KAJJ-VlRGUDjxZIZ_CEvW8iAXjUhVsbwMDOrzRKvg6O3bBEfiqCowumygOk7oGaYwQP0eF21VvKiGyNAOOm6mw6a9WyCVmFSg3imjbF2H60HI8abnr3-0xGmRo4IuNSX57BplcaKo1GXrJTaTkOTF9vzKKXdrxvoBpnx2VcZqfI69UBGQHZOs4WA7noF3kEyhZR2pP3_8XGvClEExjn_R496m0aaQ";
        System.out.println(Authorisation.VerifyAccess(token, "ISHARE.READ", "EU.EORI.NL000000005", "EU.EORI.NL000000001", "180621.CONTAINER-Z"));
    }
}
