
// $Id$

using System;
using System.Collections.Generic;
using System.Text;
using Peach.Core.Dom;
using Peach.Core.Runtime;

using NLog;

namespace Peach.Core.Mutators
{
	[Mutator("Perform common routing-key mutations")]
	public partial class RKeyMutator : Mutator
	{
		static NLog.Logger logger = LogManager.GetCurrentClassLogger();
		
		static readonly string[] values = new string[] {
			"*",
			"#",
			"+",
			".",
		};

        [Flags]
        public enum How
        {
            AddLevel = 0x001,   // Add a level to the routing '.'
            AddLevelWildcard = 0x002, // Add a single level wildcard '*'
            ReplaceLevelWildcard = 0x004, // Add a multi level wildcard '#'
            EmptyLevel = 0x008, // 
            DelLevel = 0x010, // 
		}

        // members
        //
        protected delegate string changeFcn(DataElement obj, Variant value);
        protected List<changeFcn> changeFcns;

		uint pos = 0;

		public RKeyMutator(DataElement obj)
		{
			pos = 0;
			name = "RKeyMutator";

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
			// if ((how & How.EmptyLevel) == How.EmptyLevel)
			// 	changeFcns.Add(new changeFcn(changeEmptyLevel));
			if ((how & How.DelLevel) == How.DelLevel)
				changeFcns.Add(new changeFcn(changeDelLevel));
		}

		public new static bool supportedDataElement(DataElement obj)
		{
            if (obj is Dom.URI && obj.isMutable)
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

		public static char sep = '.';
		public static string sepStr = sep.ToString();
		public static List<string> wildcards = new List<string> { "+", "#", "."};
		// ADD LEVEL
		//
		protected string changeAddLevel(DataElement obj, Variant value)
		{
			logger.Debug("MPFuzz: AddNewLevel: {0}", value);
			return value + sepStr + "t";
		}

		// SINGLE LEVEL WILDCARD
		//
		protected string changeAddLevelWildcard(DataElement obj, Variant value)
		{
			var wc = context.Random.Choice(wildcards);
			logger.Debug("MPufzz: AddLevelWildcard: {0}", wc);
			return value + sepStr + wc;
		}

		// MULTI LEVEL WILDCARD
		//
		protected string changeReplaceLevelWildcard(DataElement obj, Variant value)
		{
			logger.Debug("MPFuzz: ReplaceLevelWildcard: {0}", value);
			// convert value to string, split by '/', randomly choose a level to replace, replace it with '#'
			string[] levels = value.ToString().Split(sep);
			int index = context.Random.Next(levels.Length);
			levels[index] = context.Random.Choice(wildcards);
			return string.Join(sepStr, levels);
		}

		// EMPTY LEVEL
		//
		protected string changeEmptyLevel(DataElement obj, Variant value)
		{
			logger.Debug("MPFuzz: changeEmptyLevel: {0}", value);
			return value + sepStr + sepStr;
		}

		// DELETE LEVEL
		//
		protected string changeDelLevel(DataElement obj, Variant value)
		{
			logger.Debug("MPFuzz: changeDelLevel: {0}", value);
			string[] levels = value.ToString().Split(sep);
			int index = context.Random.Next(levels.Length);
			string[] newLevels = new string[levels.Length - 1];
			int j = 0;
			for (int i = 0; i < levels.Length; i++)
			{
				if (i != index)
				{
					newLevels[j] = levels[i];
					j++;
				}
			}
			return string.Join(sepStr, newLevels);
		}
	}
}

// end
