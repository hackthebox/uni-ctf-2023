using System;
using System.ComponentModel.DataAnnotations;

namespace Nexus_Void.Models
{
	public class UserModel
	{
		[Key]
		public int ID { get; set; }
		[Required]
		public string username { get; set; }
		[Required]
        public string password { get; set; }
    }
}

