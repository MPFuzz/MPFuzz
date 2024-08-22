
// $Id$

using System;
using System.Collections.Generic;
using System.Text;
using Peach.Core.Dom;
using Peach.Core.Runtime;

using NLog;

namespace Peach.Core.Mutators
{
	[Mutator("Perform replace synced field mutations")]
	public partial class SyncFieldMutator : Mutator
	{
		
		static NLog.Logger logger = LogManager.GetCurrentClassLogger();

		uint pos = 0;

		public SyncFieldMutator(DataElement obj)
		{
			pos = 0;
			name = "SyncFieldMutator";
		}

		public new static bool supportedDataElement(DataElement obj)
		{
            if (obj.isSync && obj.isMutable)
				return true;

			return false;
		}

		public override int count
		{
			get;
		}

		public override uint mutation
		{
			get { return pos; }
			set { pos = value; }
		}

		public override void sequentialMutation(DataElement obj)
		{
			// obj.mutationFlags = DataElement.MUTATE_DEFAULT;
			// obj.MutatedValue = new Variant(values[pos]);
		}

		public override void randomMutation(DataElement obj)
		{
			Variant replaceValue = obj.InternalValue;

			//  <Element.Type, Element.Name> -> Variant[]: public static Dictionary<Tuple<string,string>, DataElement[]> LocalFieldPool
			var element_index = new Tuple<string, string>(obj.GetType().ToString(), obj.name);

			logger.Debug("MPFuzz: obj is {0}, element_index {1}", obj.GetType(), obj.name);
			if (!SHARE.LocalFieldPool.ContainsKey(element_index))
			{
				logger.Debug("MPFuzz: LocalFieldPool does not contain key {0}", element_index);
				return;
			}
			replaceValue =  context.Random.Choice<Variant>(SHARE.LocalFieldPool[element_index]);
			logger.Debug("MPFuzz: Random choice from LocalFieldPool({1}) is {0}", replaceValue, SHARE.LocalFieldPool[element_index].Count);
			
			obj.MutatedValue = replaceValue;
			obj.mutationFlags = DataElement.MUTATE_DEFAULT;
			// obj.mutationFlags |= DataElement.MUTATE_OVERRIDE_TYPE_TRANSFORM;
			// obj.mutationFlags |= DataElement.MUTATE_OVERRIDE_RELATIONS;

		}



	}
}

// end
