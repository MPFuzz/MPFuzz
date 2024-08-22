
// $Id$

using System;
using System.Collections.Generic;
using System.Text;
using Peach.Core.Dom;
using Peach.Core.Runtime;

using NLog;

namespace Peach.Core.Mutators
{
	[Mutator("Perform common topic mutations")]
	public partial class TopicMutator : Mutator
	{
		static NLog.Logger logger = LogManager.GetCurrentClassLogger();

		static readonly string[] values = new string[] {
			"$SYS/",
			"$SYS",
		};

        [Flags]
        public enum How
        {
            AddLevel = 0x001,   // Add a level to the topic '/'
            AddLevelWildcard = 0x002, // Add a single level wildcard '+'
            ReplaceLevelWildcard = 0x004, // Add a multi level wildcard '#'
            SysTopic = 0x008, // Add a system topic '$SYS/'
            EmptyLevel = 0x010,      // Add an empty level to the topic '//'
            ReservedTopic = 0x020,  // Add a reserved topic '$' 
            // RangeSpecial = 0x040,
            // NullRange = 0x080,
            // UnNullRange = 0x100,
        }

        // members
        //
        protected delegate string changeFcn(DataElement obj, Variant value);
        protected List<changeFcn> changeFcns;

		uint pos = 0;

		public TopicMutator(DataElement obj)
		{
			pos = 0;
			name = "TopicMutator";

			How how = 0;

			foreach (var flag in Enum.GetValues(typeof(How)))
				how |= (How)flag;

			changeFcns = new List<changeFcn>();

			if ((how & How.AddLevel) == How.AddLevel)
				changeFcns.Add(new changeFcn(changeAddLevel));
			if ((how & How.AddLevelWildcard) == How.AddLevelWildcard)
				changeFcns.Add(new changeFcn(changeAddLevelWildcard));
			if ((how & How.ReplaceLevelWildcard) == How.ReplaceLevelWildcard)
				changeFcns.Add(new changeFcn(changeReplaceLevelWildcard));
			if ((how & How.SysTopic) == How.SysTopic)
				changeFcns.Add(new changeFcn(changeSysTopic));
			// if ((how & How.EmptyLevel) == How.EmptyLevel)
			// 	changeFcns.Add(new changeFcn(changeEmptyLevel));
			if ((how & How.ReservedTopic) == How.ReservedTopic)
				changeFcns.Add(new changeFcn(changeReservedTopic));
		}

		public new static bool supportedDataElement(DataElement obj)
		{
            if (obj is Dom.Topic && obj.isMutable)
				return true;

			return false;
		}

		public override int count
		{
			get { return values.Length; }
		}

		public override uint mutation
		{
			get { return pos; }
			set { pos = value; }
		}

		public override void sequentialMutation(DataElement obj)
		{
			obj.mutationFlags = DataElement.MUTATE_DEFAULT;
			obj.MutatedValue = new Variant(values[pos]);
		}

		public override void randomMutation(DataElement obj)
		{
			Variant basicValue = obj.InternalValue;
			//  <Element.Type, Element.Name> -> Variant[]: public static Dictionary<Tuple<string,string>, DataElement[]> LocalFieldPool
			var element_index = new Tuple<string, string>(obj.GetType().ToString(), obj.name);
			logger.Debug("MPFuzz: obj is {0}, element_index {1}", obj.GetType(), obj.name);
			
			if (SHARE.LocalFieldPool.ContainsKey(element_index))
			{
				basicValue =  context.Random.Choice<Variant>(SHARE.LocalFieldPool[element_index]);
				logger.Debug("MPFuzz: Random choice from LocalFieldPool({1}) is {0}", basicValue, SHARE.LocalFieldPool[element_index].Count);
			}

			obj.MutatedValue = new Variant(context.Random.Choice(changeFcns)(obj, basicValue));

			// add_mutation_probability
			if (context.Random.Next(100) < SHARE.add_mutation_probability)
				SHARE.LocalFieldPool[element_index].Add(obj.MutatedValue);


			// var tmp = context.Random.Choice<string>(values);
			// obj.MutatedValue = new Variant(tmp);

			obj.mutationFlags = DataElement.MUTATE_DEFAULT;
            // obj.mutationFlags |= DataElement.MUTATE_OVERRIDE_TYPE_TRANSFORM;
            // obj.mutationFlags |= DataElement.MUTATE_OVERRIDE_RELATIONS;
		}


		public static List<string> wildcards = new List<string> { "+", "#" , "/"};
		// ADD LEVEL
		//
		protected string changeAddLevel(DataElement obj, Variant value)
		{
			logger.Debug("MPFuzz: changeAddLevel: {0}", value);
			return value + "/" + "t";
		}

		// SINGLE LEVEL WILDCARD
		//
		protected string changeAddLevelWildcard(DataElement obj, Variant value)
		{
			var wc = context.Random.Choice(wildcards);
			logger.Debug("MPufzz: changeAddLevelWildcard: {0}", wc);
			return value + "/" + wc;
		}

		// MULTI LEVEL WILDCARD
		//
		protected string changeReplaceLevelWildcard(DataElement obj, Variant value)
		{
			logger.Debug("MPFuzz: changeReplaceLevelWildcard: {0}", value);
			// convert value to string, split by '/', randomly choose a level to replace, replace it with '#'
			string[] levels = value.ToString().Split('/');
			int index = context.Random.Next(levels.Length);
			levels[index] = context.Random.Choice(wildcards);
			return string.Join("/", levels);
		}

		// SYS TOPIC
		//
		protected string changeSysTopic(DataElement obj, Variant value)
		{
			logger.Debug("MPFuzz: changeSysTopic: {0}", value);
			return "$SYS/" + value;
		}

		// EMPTY LEVEL
		//
		protected string changeEmptyLevel(DataElement obj, Variant value)
		{
			logger.Debug("MPFuzz: changeEmptyLevel: {0}", value);
			return value + "//";
		}

		// RESERVED TOPIC
		//
		protected string changeReservedTopic(DataElement obj, Variant value)
		{
			logger.Debug("MPFuzz: changeReservedTopic: {0}", value);
			return "$" + value;
		}

	}
}

// end
