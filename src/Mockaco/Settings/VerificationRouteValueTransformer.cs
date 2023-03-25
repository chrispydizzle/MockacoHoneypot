namespace Mockaco.Settings
{
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc.Routing;
    using Microsoft.AspNetCore.Routing;
    using System.Threading.Tasks;

    class VerificationRouteValueTransformer : DynamicRouteValueTransformer
    {
        public override async ValueTask<RouteValueDictionary> TransformAsync(HttpContext httpContext, RouteValueDictionary values)
        {
            values["controller"] = "verify";
            values["action"] = "Get";

            return await Task.FromResult(values);
        }
    }
}