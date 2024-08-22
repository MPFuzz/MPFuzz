using System;
using System.Collections.Generic;
using System.Text;

using Peach.Core;
using Peach.Core.Dom;

using NLog;

namespace Peach.Core.Mutators
{
    [Mutator("ChoiceSwitch")]
	[Description("Changes which element is selected in a Choice statement.")]
	public class ChoiceSwitch : Mutator 
    {
        static NLog.Logger logger = LogManager.GetCurrentClassLogger();
        List<int> options = new List<int>();
        public ChoiceSwitch(DataElement obj)
			: base(obj)
		{
            
			name = "ChoiceSwitch";
			var asChoice = (Choice)obj;

			System.Diagnostics.Debug.Assert(asChoice.SelectedElement != null);

			for (int i = 0; i < asChoice.choiceElements.Count; ++i)
			{
				// Don't mutate to our currently selected choice
				if (asChoice.choiceElements[i] != asChoice.SelectedElement)
					options.Add(i);
			}
		}

		public new static bool supportedDataElement(DataElement obj)
		{
			var asChoice = obj as Choice;
			if (asChoice != null && asChoice.isMutable && asChoice.choiceElements.Count > 1)
				return true;

			return false;
		}

		public override uint mutation
		{
			get;
			set;
		}

		public override int count
		{
			get { return options.Count; }
		}


		public override void sequentialMutation(DataElement obj)
		{
			performMutation(obj, (int)mutation);
		}

		public override void randomMutation(DataElement obj)
		{
			performMutation(obj, context.Random.Next(0, options.Count));
		}

		void performMutation(DataElement obj, int idx)
		{
			var asChoice = (Choice)obj;
			var selection = options[idx];
            logger.Debug("performMutation(idx=" + idx + ", selection=" + selection + ")");

			asChoice.SelectElement(selection);
			obj.mutationFlags = DataElement.MUTATE_DEFAULT;
		}

    }
}