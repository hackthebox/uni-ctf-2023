namespace Nexus_Void.Helpers
{
    public class EncodeHelper
    {
        public static string Encode(string value) 
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(value);
            return System.Convert.ToBase64String(plainTextBytes);
        }
        public static string Decode(string value) 
        {
            var base64EncodedBytes = System.Convert.FromBase64String(value);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }
    }
}
