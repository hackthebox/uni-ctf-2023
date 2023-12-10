using System.ComponentModel.DataAnnotations;

namespace Nexus_Void.Models
{
    public class ProductModel
    {
        [Key]
        public int ID { get; set; }
        [Required]
        public string name { get; set; }
        [Required]
        public string image { get; set; }
        [Required]
        public string currentBid { get; set; }
        [Required]
        public string endingIn { get; set; }
        [Required]
        public string sellerName { get; set; }
        [Required]
        public string backdropImage { get; set; }


    }
}
