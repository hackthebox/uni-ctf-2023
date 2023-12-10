using Newtonsoft.Json;
using Nexus_Void.Models;

namespace Nexus_Void.Helpers
{
    public class SerializeHelper
    {
        public static string Serialize(List<ProductModel> list)
        {
            string serializedResult = JsonConvert.SerializeObject(list, new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All
            });

            string encodedData = EncodeHelper.Encode(serializedResult);
            return encodedData;
        }

        public static List<ProductModel> Deserialize(string str) 
        {
            string decodedData = EncodeHelper.Decode(str);

            var deserialized = JsonConvert.DeserializeObject(decodedData, new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All
            });

            List<ProductModel> products = deserialized as List<ProductModel>;

            return products;
        }
    }
}
